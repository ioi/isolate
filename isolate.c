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
#include <time.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>

#define NONRET __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define ARRAY_SIZE(a) (int)(sizeof(a)/sizeof(a[0]))

static int timeout;			/* milliseconds */
static int wall_timeout;
static int extra_timeout;
static int pass_environ;
static int verbose;
static int memory_limit;
static int stack_limit;
static char *redir_stdin, *redir_stdout, *redir_stderr;
static char *set_cwd;

static pid_t box_pid;
static volatile int timer_tick;
static struct timeval start_time;
static int ticks_per_sec;
static int partial_line;

static int mem_peak_kb;
static int total_ms, wall_ms;

static void die(char *msg, ...) NONRET;
static void sample_mem_peak(void);

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
  meta_printf("mem:%llu\n", (unsigned long long) mem_peak_kb * 1024);
}

/*** Messages and exits ***/

static void NONRET
box_exit(int rc)
{
  if (box_pid > 0)
    {
      sample_mem_peak();
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

/*** FIXME ***/

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
sample_mem_peak(void)
{
  /*
   *  We want to find out the peak memory usage of the process, which is
   *  maintained by the kernel, but unforunately it gets lost when the
   *  process exits (it is not reported in struct rusage). Therefore we
   *  have to sample it whenever we suspect that the process is about
   *  to exit.
   */
  char buf[PROC_BUF_SIZE], *x;
  static int proc_status_fd;
  read_proc_file(buf, "status", &proc_status_fd);

  x = buf;
  while (*x)
    {
      char *key = x;
      while (*x && *x != ':' && *x != '\n')
	x++;
      if (!*x || *x == '\n')
	break;
      *x++ = 0;
      while (*x == ' ' || *x == '\t')
	x++;

      char *val = x;
      while (*x && *x != '\n')
	x++;
      if (!*x)
	break;
      *x++ = 0;

      if (!strcmp(key, "VmPeak"))
	{
	  int peak = atoi(val);
	  if (peak > mem_peak_kb)
	    mem_peak_kb = peak;
	}
    }

  if (verbose > 1)
    msg("[mem-peak: %u KB]\n", mem_peak_kb);
}

static void
boxkeeper(void)
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
      p = wait4(box_pid, &stat, WUNTRACED, &rus);
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
	  fprintf(stderr, "OK (%d.%03d sec real, %d.%03d sec wall, %d MB)\n",
	      total_ms/1000, total_ms%1000,
	      wall_ms/1000, wall_ms%1000,
	      (mem_peak_kb + 1023) / 1024);
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

static void
box_inside(int argc, char **argv)
{
  struct rlimit rl;
  char *args[argc+1];

  memcpy(args, argv, argc * sizeof(char *));
  args[argc] = NULL;
  if (set_cwd && chdir(set_cwd))
    die("chdir: %m");
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

  char **env = setup_environment();
  execve(args[0], args, env);
  die("execve(\"%s\"): %m", args[0]);
}

// FIXME: Prune (and also the getopt string)
static void
usage(void)
{
  fprintf(stderr, "Invalid arguments!\n");
  printf("\
Usage: box [<options>] -- <command> <arguments>\n\
\n\
Options:\n\
-a <level>\tSet file access level (0=none, 1=cwd, 2=/etc,/lib,..., 3=whole fs, 9=no checks; needs -f)\n\
-c <dir>\tChange directory to <dir> first\n\
-e\t\tInherit full environment of the parent process\n\
-E <var>\tInherit the environment variable <var> from the parent process\n\
-E <var>=<val>\tSet the environment variable <var> to <val>; unset it if <var> is empty\n\
-f\t\tFilter system calls (-ff=very restricted)\n\
-i <file>\tRedirect stdin from <file>\n\
-k <size>\tLimit stack size to <size> KB (default: 0=unlimited)\n\
-m <size>\tLimit address space to <size> KB\n\
-M <file>\tOutput process information to <file> (name:value)\n\
-o <file>\tRedirect stdout to <file>\n\
-p <path>\tPermit access to the specified path (or subtree if it ends with a `/')\n\
-p <path>=<act>\tDefine action for the specified path (<act>=yes/no)\n\
-r <file>\tRedirect stderr to <file>\n\
-s <sys>\tPermit the specified syscall (be careful)\n\
-s <sys>=<act>\tDefine action for the specified syscall (<act>=yes/no/file)\n\
-t <time>\tSet run time limit (seconds, fractions allowed)\n\
-T\t\tAllow syscalls for measuring run time\n\
-v\t\tBe verbose (use multiple times for even more verbosity)\n\
-w <time>\tSet wall clock time limit (seconds, fractions allowed)\n\
-x <time>\tSet extra timeout, before which a timing-out program is not yet killed,\n\
\t\tso that its real execution time is reported (seconds, fractions allowed)\n\
");
  exit(2);
}

int
main(int argc, char **argv)
{
  int c;
  uid_t uid;

  while ((c = getopt(argc, argv, "a:c:eE:fi:k:m:M:o:p:r:s:t:Tvw:x:")) >= 0)
    switch (c)
      {
      case 'c':
	set_cwd = optarg;
	break;
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
      default:
	usage();
      }
  if (optind >= argc)
    usage();

  uid = geteuid();
  if (setreuid(uid, uid) < 0)
    die("setreuid: %m");
  box_pid = fork();
  if (box_pid < 0)
    die("fork: %m");
  if (!box_pid)
    box_inside(argc-optind, argv+optind);
  else
    boxkeeper();
  die("Internal error: fell over edge of the world");
}
