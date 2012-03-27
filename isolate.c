/*
 *	A Process Isolator based in Linux Containers
 *
 *	(c) 2012 Martin Mares <mj@ucw.cz>
 */

#define _GNU_SOURCE

#include "autoconf.h"

// FIXME: prune
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <sched.h>
#include <time.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/stat.h>

#define NONRET __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define ARRAY_SIZE(a) (int)(sizeof(a)/sizeof(a[0]))

// FIXME: Make configurable, probably in compile time
#define BOX_DIR "/tmp/box"
#define BOX_UID 60000
#define BOX_GID 60000

static int timeout;			/* milliseconds */
static int wall_timeout;
static int extra_timeout;
static int pass_environ;
static int verbose;
static int memory_limit;
static int stack_limit;
static char *redir_stdin, *redir_stdout, *redir_stderr;

static uid_t orig_uid;
static gid_t orig_gid;

static pid_t box_pid;
static volatile sig_atomic_t timer_tick;
static struct timeval start_time;
static int ticks_per_sec;
static int partial_line;
static char cleanup_cmd[256];

static int total_ms, wall_ms;

static void die(char *msg, ...) NONRET;

/*** Meta-files ***/

static FILE *metafile;

static void
meta_open(const char *name)
{
  if (!strcmp(name, "-"))
    {
      metafile = stdout;
      return;
    }
  metafile = fopen(name, "w");
  if (!metafile)
    die("Failed to open metafile '%s'",name);
}

static void
meta_close(void)
{
  if (metafile && metafile != stdout)
    fclose(metafile);
}

static void __attribute__((format(printf,1,2)))
meta_printf(const char *fmt, ...)
{
  if (!metafile)
    return;

  va_list args;
  va_start(args, fmt);
  vfprintf(metafile, fmt, args);
  va_end(args);
}

static void
final_stats(struct rusage *rus)
{
  struct timeval total, now, wall;
  timeradd(&rus->ru_utime, &rus->ru_stime, &total);
  total_ms = total.tv_sec*1000 + total.tv_usec/1000;
  gettimeofday(&now, NULL);
  timersub(&now, &start_time, &wall);
  wall_ms = wall.tv_sec*1000 + wall.tv_usec/1000;

  meta_printf("time:%d.%03d\n", total_ms/1000, total_ms%1000);
  meta_printf("time-wall:%d.%03d\n", wall_ms/1000, wall_ms%1000);
}

/*** Messages and exits ***/

static void
xsystem(const char *cmd)
{
  int ret = system(cmd);
  if (ret < 0)
    die("system(\"%s\"): %m", cmd);
  if (!WIFEXITED(ret) || WEXITSTATUS(ret))
    die("system(\"%s\"): Exited with status %d", cmd, ret);
}

static void NONRET
box_exit(int rc)
{
  if (box_pid > 0)
    {
      kill(-box_pid, SIGKILL);
      kill(box_pid, SIGKILL);
      meta_printf("killed:1\n");

      struct rusage rus;
      int p, stat;
      do
	p = wait4(box_pid, &stat, 0, &rus);
      while (p < 0 && errno == EINTR);
      if (p < 0)
	fprintf(stderr, "UGH: Lost track of the process (%m)\n");
      else
	final_stats(&rus);
    }

  if (rc < 2 && cleanup_cmd[0])
    xsystem(cleanup_cmd);

  meta_close();
  exit(rc);
}

static void
flush_line(void)
{
  if (partial_line)
    fputc('\n', stderr);
  partial_line = 0;
}

/* Report an error of the sandbox itself */
static void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  flush_line();
  char buf[1024];
  vsnprintf(buf, sizeof(buf), msg, args);
  meta_printf("status:XX\nmessage:%s\n", buf);
  fputs(buf, stderr);
  fputc('\n', stderr);
  box_exit(2);
}

/* Report an error of the program inside the sandbox */
static void NONRET __attribute__((format(printf,1,2)))
err(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  flush_line();
  if (msg[0] && msg[1] && msg[2] == ':' && msg[3] == ' ')
    {
      meta_printf("status:%c%c\n", msg[0], msg[1]);
      msg += 4;
    }
  char buf[1024];
  vsnprintf(buf, sizeof(buf), msg, args);
  meta_printf("message:%s\n", buf);
  fputs(buf, stderr);
  fputc('\n', stderr);
  box_exit(1);
}

/* Write a message, but only if in verbose mode */
static void __attribute__((format(printf,1,2)))
msg(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  if (verbose)
    {
      int len = strlen(msg);
      if (len > 0)
        partial_line = (msg[len-1] != '\n');
      vfprintf(stderr, msg, args);
      fflush(stderr);
    }
  va_end(args);
}

static void *
xmalloc(size_t size)
{
  void *p = malloc(size);
  if (!p)
    die("Out of memory");
  return p;
}

/*** Environment rules ***/

struct env_rule {
  char *var;			// Variable to match
  char *val;			// ""=clear, NULL=inherit
  int var_len;
  struct env_rule *next;
};

static struct env_rule *first_env_rule;
static struct env_rule **last_env_rule = &first_env_rule;

static struct env_rule default_env_rules[] = {
  { "LIBC_FATAL_STDERR_", "1" }
};

static int
set_env_action(char *a0)
{
  struct env_rule *r = xmalloc(sizeof(*r) + strlen(a0) + 1);
  char *a = (char *)(r+1);
  strcpy(a, a0);

  char *sep = strchr(a, '=');
  if (sep == a)
    return 0;
  r->var = a;
  if (sep)
    {
      *sep++ = 0;
      r->val = sep;
    }
  else
    r->val = NULL;
  *last_env_rule = r;
  last_env_rule = &r->next;
  r->next = NULL;
  return 1;
}

static int
match_env_var(char *env_entry, struct env_rule *r)
{
  if (strncmp(env_entry, r->var, r->var_len))
    return 0;
  return (env_entry[r->var_len] == '=');
}

static void
apply_env_rule(char **env, int *env_sizep, struct env_rule *r)
{
  // First remove the variable if already set
  int pos = 0;
  while (pos < *env_sizep && !match_env_var(env[pos], r))
    pos++;
  if (pos < *env_sizep)
    {
      (*env_sizep)--;
      env[pos] = env[*env_sizep];
      env[*env_sizep] = NULL;
    }

  // What is the new value?
  char *new;
  if (r->val)
    {
      if (!r->val[0])
	return;
      new = xmalloc(r->var_len + 1 + strlen(r->val) + 1);
      sprintf(new, "%s=%s", r->var, r->val);
    }
  else
    {
      pos = 0;
      while (environ[pos] && !match_env_var(environ[pos], r))
	pos++;
      if (!(new = environ[pos]))
	return;
    }

  // Add it at the end of the array
  env[(*env_sizep)++] = new;
  env[*env_sizep] = NULL;
}

static char **
setup_environment(void)
{
  // Link built-in rules with user rules
  for (int i=ARRAY_SIZE(default_env_rules)-1; i >= 0; i--)
    {
      default_env_rules[i].next = first_env_rule;
      first_env_rule = &default_env_rules[i];
    }

  // Scan the original environment
  char **orig_env = environ;
  int orig_size = 0;
  while (orig_env[orig_size])
    orig_size++;

  // For each rule, reserve one more slot and calculate length
  int num_rules = 0;
  for (struct env_rule *r = first_env_rule; r; r=r->next)
    {
      num_rules++;
      r->var_len = strlen(r->var);
    }

  // Create a new environment
  char **env = xmalloc((orig_size + num_rules + 1) * sizeof(char *));
  int size;
  if (pass_environ)
    {
      memcpy(env, environ, orig_size * sizeof(char *));
      size = orig_size;
    }
  else
    size = 0;
  env[size] = NULL;

  // Apply the rules one by one
  for (struct env_rule *r = first_env_rule; r; r=r->next)
    apply_env_rule(env, &size, r);

  // Return the new env and pass some gossip
  if (verbose > 1)
    {
      fprintf(stderr, "Passing environment:\n");
      for (int i=0; env[i]; i++)
	fprintf(stderr, "\t%s\n", env[i]);
    }
  return env;
}

/*** The keeper process ***/

static void
signal_alarm(int unused UNUSED)
{
  /* Time limit checks are synchronous, so we only schedule them there. */
  timer_tick = 1;
  alarm(1);
}

static void
signal_int(int unused UNUSED)
{
  /* Interrupts are fatal, so no synchronization requirements. */
  meta_printf("exitsig:%d\n", SIGINT);
  err("SG: Interrupted");
}

#define PROC_BUF_SIZE 4096
static void
read_proc_file(char *buf, char *name, int *fdp)
{
  int c;

  if (!*fdp)
    {
      sprintf(buf, "/proc/%d/%s", (int) box_pid, name);
      *fdp = open(buf, O_RDONLY);
      if (*fdp < 0)
	die("open(%s): %m", buf);
    }
  lseek(*fdp, 0, SEEK_SET);
  if ((c = read(*fdp, buf, PROC_BUF_SIZE-1)) < 0)
    die("read on /proc/$pid/%s: %m", name);
  if (c >= PROC_BUF_SIZE-1)
    die("/proc/$pid/%s too long", name);
  buf[c] = 0;
}

static void
check_timeout(void)
{
  if (wall_timeout)
    {
      struct timeval now, wall;
      int wall_ms;
      gettimeofday(&now, NULL);
      timersub(&now, &start_time, &wall);
      wall_ms = wall.tv_sec*1000 + wall.tv_usec/1000;
      if (wall_ms > wall_timeout)
        err("TO: Time limit exceeded (wall clock)");
      if (verbose > 1)
        fprintf(stderr, "[wall time check: %d msec]\n", wall_ms);
    }
  if (timeout)
    {
      char buf[PROC_BUF_SIZE], *x;
      int utime, stime, ms;
      static int proc_stat_fd;
      read_proc_file(buf, "stat", &proc_stat_fd);
      x = buf;
      while (*x && *x != ' ')
	x++;
      while (*x == ' ')
	x++;
      if (*x++ != '(')
	die("proc stat syntax error 1");
      while (*x && (*x != ')' || x[1] != ' '))
	x++;
      while (*x == ')' || *x == ' ')
	x++;
      if (sscanf(x, "%*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %d %d", &utime, &stime) != 2)
	die("proc stat syntax error 2");
      ms = (utime + stime) * 1000 / ticks_per_sec;
      if (verbose > 1)
	fprintf(stderr, "[time check: %d msec]\n", ms);
      if (ms > timeout && ms > extra_timeout)
	err("TO: Time limit exceeded");
    }
}

static void
box_keeper(void)
{
  struct sigaction sa;

  bzero(&sa, sizeof(sa));
  sa.sa_handler = signal_int;
  sigaction(SIGINT, &sa, NULL);

  gettimeofday(&start_time, NULL);
  ticks_per_sec = sysconf(_SC_CLK_TCK);
  if (ticks_per_sec <= 0)
    die("Invalid ticks_per_sec!");

  if (timeout || wall_timeout)
    {
      sa.sa_handler = signal_alarm;
      sigaction(SIGALRM, &sa, NULL);
      alarm(1);
    }

  for(;;)
    {
      struct rusage rus;
      int stat;
      pid_t p;
      if (timer_tick)
	{
	  check_timeout();
	  timer_tick = 0;
	}
      p = wait4(box_pid, &stat, 0, &rus);
      if (p < 0)
	{
	  if (errno == EINTR)
	    continue;
	  die("wait4: %m");
	}
      if (p != box_pid)
	die("wait4: unknown pid %d exited!", p);
      if (WIFEXITED(stat))
	{
	  box_pid = 0;
	  final_stats(&rus);
	  if (WEXITSTATUS(stat))
	    {
	      // FIXME: Recognize internal errors during setup
	      meta_printf("exitcode:%d\n", WEXITSTATUS(stat));
	      err("RE: Exited with error status %d", WEXITSTATUS(stat));
	    }
	  if (timeout && total_ms > timeout)
	    err("TO: Time limit exceeded");
	  if (wall_timeout && wall_ms > wall_timeout)
	    err("TO: Time limit exceeded (wall clock)");
	  flush_line();
	  fprintf(stderr, "OK (%d.%03d sec real, %d.%03d sec wall)\n",
	      total_ms/1000, total_ms%1000,
	      wall_ms/1000, wall_ms%1000);
	  box_exit(0);
	}
      if (WIFSIGNALED(stat))
	{
	  box_pid = 0;
	  meta_printf("exitsig:%d\n", WTERMSIG(stat));
	  final_stats(&rus);
	  err("SG: Caught fatal signal %d", WTERMSIG(stat));
	}
      if (WIFSTOPPED(stat))
	{
	  box_pid = 0;
	  meta_printf("exitsig:%d\n", WSTOPSIG(stat));
	  final_stats(&rus);
	  err("SG: Stopped by signal %d", WSTOPSIG(stat));
	}
      else
	die("wait4: unknown status %x, giving up!", stat);
    }
}

/*** The process running inside the box ***/

static void
setup_root(void)
{
  umask(0027);

  if (mkdir("root", 0777) < 0 && errno != EEXIST)
    die("mkdir('root'): %m");

  if (mount("none", "root", "tmpfs", 0, "mode=755") < 0)
    die("Cannot mount root ramdisk: %m");

  // FIXME: Make the list of bind-mounts configurable
  // FIXME: Virtual /dev?
  // FIXME: Read-only mounts?

  static const char * const dirs[] = { "box", "/bin", "/lib", "/usr", "/dev" };
  for (int i=0; i < ARRAY_SIZE(dirs); i++)
    {
      const char *d = dirs[i];
      char buf[1024];	// FIXME
      sprintf(buf, "root/%s", (d[0] == '/' ? d+1 : d));
      msg("Binding %s on %s\n", d, buf);
      if (mkdir(buf, 0777) < 0)
	die("mkdir(%s): %m", buf);
      if (mount(d, buf, "none", MS_BIND | MS_NOSUID | MS_NODEV, "") < 0)
	die("Cannot bind %s on %s: %m", d, buf);
    }

  if (mkdir("root/proc", 0777) < 0)
    die("Cannot create proc: %m");
  if (mount("none", "root/proc", "proc", 0, "") < 0)
    die("Cannot mount proc: %m");

  if (chroot("root") < 0)
    die("Chroot failed: %m");

  if (chdir("root/box") < 0)
    die("Cannot change current directory: %m");
}

static int
box_inside(void *arg)
{
  char **argv = arg;
  int argc = 0;
  while (argv[argc])
    argc++;

  struct rlimit rl;
  char *args[argc+1];

  memcpy(args, argv, argc * sizeof(char *));
  args[argc] = NULL;

  setup_root();

  if (setresgid(BOX_GID, BOX_GID, BOX_GID) < 0)
    die("setresgid: %m");
  if (setgroups(0, NULL) < 0)
    die("setgroups: %m");
  if (setresuid(BOX_UID, BOX_UID, BOX_UID) < 0)
    die("setresuid: %m");

  if (redir_stdin)
    {
      close(0);
      if (open(redir_stdin, O_RDONLY) != 0)
	die("open(\"%s\"): %m", redir_stdin);
    }
  if (redir_stdout)
    {
      close(1);
      if (open(redir_stdout, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 1)
	die("open(\"%s\"): %m", redir_stdout);
    }
  if (redir_stderr)
    {
      close(2);
      if (open(redir_stderr, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 2)
	die("open(\"%s\"): %m", redir_stderr);
    }
  else
    dup2(1, 2);
  setpgrp();

  if (memory_limit)
    {
      rl.rlim_cur = rl.rlim_max = memory_limit * 1024;
      if (setrlimit(RLIMIT_AS, &rl) < 0)
	die("setrlimit(RLIMIT_AS): %m");
    }

  rl.rlim_cur = rl.rlim_max = (stack_limit ? (rlim_t)stack_limit * 1024 : RLIM_INFINITY);
  if (setrlimit(RLIMIT_STACK, &rl) < 0)
    die("setrlimit(RLIMIT_STACK): %m");

  rl.rlim_cur = rl.rlim_max = 64;
  if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
    die("setrlimit(RLIMIT_NOFILE): %m");

  // FIXME: Create multi-process mode
  rl.rlim_cur = rl.rlim_max = 1;
  if (setrlimit(RLIMIT_NPROC, &rl) < 0)
    die("setrlimit(RLIMIT_NPROC): %m");

  rl.rlim_cur = rl.rlim_max = 0;
  if (setrlimit(RLIMIT_MEMLOCK, &rl) < 0)
    die("setrlimit(RLIMIT_MEMLOCK): %m");

  char **env = setup_environment();
  execve(args[0], args, env);
  die("execve(\"%s\"): %m", args[0]);
}

static void
prepare(void)
{
  msg("Preparing sandbox directory\n");
  xsystem("rm -rf box");
  if (mkdir("box", 0700) < 0)
    die("Cannot create box: %m");
  if (chown("box", orig_uid, orig_gid) < 0)
    die("Cannot chown box: %m");
}

static void
cleanup(void)
{
  msg("Deleting sandbox directory\n");
  xsystem("rm -rf box");
}

static void
run(char **argv)
{
  struct stat st;
  if (stat("box", &st) < 0 || !S_ISDIR(st.st_mode))
    die("Box directory not found, did you run `isolate --prepare'?");

  char cmd[256];
  snprintf(cmd, sizeof(cmd), "chown -R %d.%d box", BOX_UID, BOX_GID);
  xsystem(cmd);
  snprintf(cleanup_cmd, sizeof(cleanup_cmd), "chown -R %d.%d box", orig_uid, orig_gid);

  box_pid = clone(
    box_inside,			// Function to execute as the body of the new process
    argv,			// Pass our stack
    SIGCHLD | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID,
    argv);			// Pass the arguments
  if (box_pid < 0)
    die("clone: %m");
  if (!box_pid)
    die("clone returned 0");
  box_keeper();
}

static void
show_version(void)
{
  // FIXME
  printf("Process isolator 0.0\n");
  printf("(c) 2012 Martin Mares <mj@ucw.cz>\n\n");
  printf("Sandbox directory: %s\n", BOX_DIR);
  printf("Sandbox credentials: uid=%u gid=%u\n", BOX_UID, BOX_GID);
}

static void
usage(void)
{
  fprintf(stderr, "Invalid arguments!\n");
  printf("\
Usage: isolate [<options>] <command>\n\
\n\
Options:\n\
-e, --full-env\t\tInherit full environment of the parent process\n\
-E, --env=<var>\tInherit the environment variable <var> from the parent process\n\
-E, --env=<var>=<val>\tSet the environment variable <var> to <val>; unset it if <var> is empty\n\
-i, --stdin=<file>\tRedirect stdin from <file>\n\
-k, --stack=<size>\tLimit stack size to <size> KB (default: 0=unlimited)\n\
-m, --mem=<size>\tLimit address space to <size> KB\n\
-M, --meta=<file>\tOutput process information to <file> (name:value)\n\
-o, --stdout=<file>\tRedirect stdout to <file>\n\
-r, --stderr=<file>\tRedirect stderr to <file>\n\
-t, --time=<time>\tSet run time limit (seconds, fractions allowed)\n\
-v, --verbose\t\tBe verbose (use multiple times for even more verbosity)\n\
-w, --wall-time=<time>\tSet wall clock time limit (seconds, fractions allowed)\n\
-x, --extra-time=<time>\tSet extra timeout, before which a timing-out program is not yet killed,\n\
\t\t\tso that its real execution time is reported (seconds, fractions allowed)\n\
\n\
Commands:\n\
    --prepare\t\tInitialize sandbox\n\
    --run -- <cmd> ...\tRun given command within sandbox\n\
    --cleanup\t\tClean up sandbox\n\
    --version\t\tDisplay program version and configuration\n\
");
  exit(2);
}

enum opt_code {
  OPT_PREPARE = 256,
  OPT_RUN,
  OPT_CLEANUP,
  OPT_VERSION,
};

static const char short_opts[] = "eE:i:k:m:M:o:r:t:vw:x:";

static const struct option long_opts[] = {
  { "full-env",		0, NULL, 'e' },
  { "env",		1, NULL, 'E' },
  { "stdin",		1, NULL, 'i' },
  { "stack",		1, NULL, 'k' },
  { "mem",		1, NULL, 'm' },
  { "meta",		1, NULL, 'M' },
  { "stdout",		1, NULL, 'o' },
  { "stderr",		1, NULL, 'r' },
  { "time",		1, NULL, 't' },
  { "verbose",		0, NULL, 'v' },
  { "wall-time",	1, NULL, 'w' },
  { "extra-time",	1, NULL, 'x' },
  { "prepare",		0, NULL, OPT_PREPARE },
  { "run",		0, NULL, OPT_RUN },
  { "cleanup",		0, NULL, OPT_CLEANUP },
  { "version",		0, NULL, OPT_VERSION },
  { NULL,		0, NULL, 0 }
};

int
main(int argc, char **argv)
{
  int c;
  enum opt_code mode = 0;

  while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) >= 0)
    switch (c)
      {
      case 'e':
	pass_environ = 1;
	break;
      case 'E':
	if (!set_env_action(optarg))
	  usage();
	break;
      case 'k':
	stack_limit = atol(optarg);
	break;
      case 'i':
	redir_stdin = optarg;
	break;
      case 'm':
	memory_limit = atol(optarg);
	break;
      case 'M':
	meta_open(optarg);
	break;
      case 'o':
	redir_stdout = optarg;
	break;
      case 'r':
	redir_stderr = optarg;
	break;
      case 't':
	timeout = 1000*atof(optarg);
	break;
      case 'v':
	verbose++;
	break;
      case 'w':
	wall_timeout = 1000*atof(optarg);
	break;
      case 'x':
	extra_timeout = 1000*atof(optarg);
	break;
      case OPT_PREPARE:
      case OPT_RUN:
      case OPT_CLEANUP:
      case OPT_VERSION:
	mode = c;
	break;
      default:
	usage();
      }

  if (!mode)
    usage();
  if (mode == OPT_VERSION)
    {
      show_version();
      return 0;
    }

  if (geteuid())
    die("Must be started as root");
  orig_uid = getuid();
  orig_gid = getgid();

  if (chdir(BOX_DIR) < 0)
    die("chdir(%s): %m", BOX_DIR);

  switch (mode)
    {
    case OPT_PREPARE:
      if (optind < argc)
	usage();
      prepare();
      break;
    case OPT_RUN:
      if (optind >= argc)
	usage();
      run(argv+optind);
      break;
    case OPT_CLEANUP:
      if (optind < argc)
	usage();
      cleanup();
      break;
    default:
      die("Internal error: mode mismatch");
    }
  exit(0);
}
