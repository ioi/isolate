/*
 *	A Process Isolator based on Linux Containers
 *
 *	(c) 2012-2024 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* May not be defined in older glibc headers */
#ifndef MS_PRIVATE
#warning "Working around old glibc: no MS_PRIVATE"
#define MS_PRIVATE (1 << 18)
#endif
#ifndef MS_REC
#warning "Working around old glibc: no MS_REC"
#define MS_REC     (1 << 14)
#endif

/*
 * Theory of operation
 *
 * Generally, we want to run a process inside a namespace/cgroup and watch it
 * from the outside. However, the reality is a little bit more complicated as we
 * do not want the inside process to become the init process of the PID namespace
 * (we want to have all signals properly delivered).
 *
 * We are running three processes:
 *
 *   - Keeper process (root privileges, parent namespace, parent cgroups)
 *   - Proxy process (UID/GID of the calling user, init process of the child
 *     namespace, parent cgroups)
 *   - Inside process (per-box UID/GID, child namespace, child cgroups)
 *
 * The proxy process just waits for the inside process to exit and then it passes
 * the exit status to the keeper.
 *
 * We use two pipes:
 *
 *   - Error pipe for error messages produced by the proxy process and the early
 *     stages of the inside process (until exec()). Listened to by the keeper.
 *   - Status pipe for passing the PID of the inside process and its exit status
 *     from the proxy to the keeper.
 */

#define TIMER_INTERVAL_US 100000

static int timeout;			/* milliseconds */
static int wall_timeout;
static int extra_timeout;
int pass_environ;
int verbose;
static int silent;
static int fsize_limit;
static int memory_limit;
static int stack_limit;
static int open_file_limit = 64;
static int core_limit;
int block_quota;
int inode_quota;
static int max_processes = 1;
static char *redir_stdin, *redir_stdout, *redir_stderr;
static int redir_stderr_to_stdout;
static char *set_cwd;
static int share_net;
static int inherit_fds;
static int default_dirs = 1;
static int tty_hack;
static bool special_files;
static bool wait_if_busy;
static int as_uid = -1;
static int as_gid = -1;

int cg_enable;
int cg_memory_limit;

int box_id;
static char box_dir[1024];
static pid_t box_pid;
static pid_t proxy_pid;

uid_t box_uid;
gid_t box_gid;
uid_t orig_uid;
gid_t orig_gid;
static bool invoked_by_root;

static int partial_line;
static int cleanup_ownership;

static struct timespec start_time;
static int ticks_per_sec;
static int total_ms, wall_ms;
static volatile sig_atomic_t timer_tick, interrupt;

static int error_pipes[2];
static int write_errors_to_fd;
static int read_errors_from_fd;

static int status_pipes[2];

static int get_wall_time_ms(void);
static int get_run_time_ms(struct rusage *rus);

/*** Locks ***/

/*
 *  Whenever a sandbox is initialized, a lock file is created, which
 *  records which user owns the sandbox and whether the cgroup mode is used.
 *  Atempts to use the same sandbox by a different user are refused.
 *
 *  The lock file is locked whenever Isolate runs in that sandbox.
 */

#define LOCK_MAGIC 0x48736f6c

struct lock_record {
  uint32_t magic;
  uint32_t owner_uid;
  unsigned char cg_enabled;
  unsigned char is_initialized;
  unsigned char rfu[2];
};

static int lock_fd = -1;
static struct lock_record lock;

static void
lock_write(void)
{
  int n = pwrite(lock_fd, &lock, sizeof(lock), 0);
  if (n != sizeof(lock))
    die("Cannot write lock file: %m");
}

static bool
lock_box(bool is_init)
{
  if (!dir_exists(cf_lock_root))
    make_dir(cf_lock_root);

  char lock_name[256];
  int name_len = snprintf(lock_name, sizeof(lock_name), "%s/%d", cf_lock_root, box_id);
  assert(name_len < (int) sizeof(lock_name));

  lock_fd = open(lock_name, O_RDWR | (is_init ? O_CREAT : 0), 0666);
  if (lock_fd < 0)
    {
      if (errno == ENOENT)
	return false;
      die("Cannot open %s: %m", lock_name);
    }

  if (flock(lock_fd, LOCK_EX | (wait_if_busy ? 0 : LOCK_NB)) < 0)
    {
      if (errno == EWOULDBLOCK)
	die("This box is currently in use by another process");
      die("Cannot lock %s: %m", lock_name);
    }

  int n = read(lock_fd, &lock, sizeof(lock));
  if (n < 0)
    die("Cannot read %s: %m", lock_name);

  if (n > 0)
    {
      if (n != sizeof(lock) || lock.magic != LOCK_MAGIC)
	die("Lock file %s has incompatible format", lock_name);
      if (lock.is_initialized && lock.owner_uid != orig_uid && !invoked_by_root)
	die("This box belongs to a different user (uid %d)", lock.owner_uid);
      if (lock.cg_enabled != cg_enable)
	die("This box was initialized with an incompatible control group mode");
    }

  if (is_init)
    {
      lock.magic = LOCK_MAGIC;
      lock.owner_uid = orig_uid;
      lock.cg_enabled = cg_enable;
      lock.is_initialized = 0;
      lock_write();
      return true;
    }
  else
    {
      if (n > 0)
	{
	  if (!lock.is_initialized)
	    die("This box was not initialized properly");
	  return true;
	}
      else
	{
	  // This means that somebody else is just creating the sandbox and we locked it
	  // between his creation of the lock file and locking it.
	  return false;
	}
    }

  // The acquired lock will be automatically released on process exit.
}

static void
lock_close(void)
{
  if (lock_fd >= 0)
    {
      close(lock_fd);
      lock_fd = -1;
    }
}

static void
lock_remove(void)
{
  // To avoid race conditions, we must never unlink lock files.
  // We just truncate them to zero length.
  assert(lock_fd >= 0);
  if (ftruncate(lock_fd, 0) < 0)
    die("Cannot truncate lock file: %m");
  close(lock_fd);
  lock_fd = -1;
}

/*** Messages and exits ***/

static void
final_stats(struct rusage *rus)
{
  total_ms = get_run_time_ms(rus);
  wall_ms = get_wall_time_ms();

  meta_printf("time:%d.%03d\n", total_ms/1000, total_ms%1000);
  meta_printf("time-wall:%d.%03d\n", wall_ms/1000, wall_ms%1000);
  meta_printf("max-rss:%ld\n", rus->ru_maxrss);
  meta_printf("csw-voluntary:%ld\n", rus->ru_nvcsw);
  meta_printf("csw-forced:%ld\n", rus->ru_nivcsw);

  cg_stats();
}

static void NONRET
box_exit(int rc)
{
  if (proxy_pid > 0)
    {
      if (box_pid > 0)
	{
	  kill(-box_pid, SIGKILL);
	  kill(box_pid, SIGKILL);
	}
      if (cg_enable)
	{
	  /*
	   *  In non-CG mode, we must not kill the proxy explicitly.
	   *  This is important, because the proxy could exit before the box
	   *  completes its exit, causing rusage of the box to be lost.
	   *
	   *  In CG mode, we must kill the proxy, because it is the init
	   *  process of the CG and killing it causes all other processes
	   *  inside the CG to be killed. However, we do not care about
	   *  rusage.
	   */
	  kill(-proxy_pid, SIGKILL);
	  kill(proxy_pid, SIGKILL);
	}
      meta_printf("killed:1\n");

      /*
       *  The rusage will contain time spent by the proxy and its children (i.e., the box).
       *  (See comments on killing of the proxy above, though.)
       */
      struct rusage rus;
      int p, stat;
      do
	p = wait4(proxy_pid, &stat, 0, &rus);
      while (p < 0 && errno == EINTR);
      if (p < 0)
	fprintf(stderr, "UGH: Lost track of the process (%m)\n");
      else
	final_stats(&rus);
    }

  if (tty_hack && isatty(1))
    {
      /*
       *  If stdout is a tty, make us the foreground process group again.
       *  We do not need it (we ignore SIGTTOU anyway), but programs executed
       *  after our exit will.
       */
      tcsetpgrp(1, getpgrp());
    }

  if (rc < 2 && cleanup_ownership)
    chowntree("box", orig_uid, orig_gid, special_files);

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
void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  char buf[1024];
  int n = vsnprintf(buf, sizeof(buf), msg, args);

  // If the child processes are still running, show no mercy.
  if (box_pid > 0)
    {
      kill(-box_pid, SIGKILL);
      kill(box_pid, SIGKILL);
    }
  if (proxy_pid > 0)
    {
      kill(-proxy_pid, SIGKILL);
      kill(proxy_pid, SIGKILL);
    }

  if (write_errors_to_fd)
    {
      // We are inside the box, have to use error pipe for error reporting.
      // We hope that the whole error message fits in PIPE_BUF bytes.
      write(write_errors_to_fd, buf, n);
      exit(2);
    }

  // Otherwise, we in the box keeper process, so we report errors normally
  flush_line();
  meta_printf("status:XX\nmessage:%s\n", buf);
  fputs(buf, stderr);
  fputc('\n', stderr);
  box_exit(2);
}

/* Report an error of the program inside the sandbox */
void NONRET __attribute__((format(printf,1,2)))
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
  if (!silent)
    {
      fputs(buf, stderr);
      fputc('\n', stderr);
    }
  box_exit(1);
}

/* Write a message, but only if in verbose mode */
void __attribute__((format(printf,1,2)))
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

/*** Signal handling in keeper process ***/

/*
 *   Signal handling is tricky. We must set up signal handlers before
 *   we start the child process (and reset them in the child process).
 *   Otherwise, there is a short time window where a SIGINT can kill
 *   us and leave the child process running.
 */

struct signal_rule {
  int signum;
  enum { SIGNAL_IGNORE, SIGNAL_INTERRUPT, SIGNAL_FATAL } action;
};

static const struct signal_rule signal_rules[] = {
  { SIGHUP,	SIGNAL_INTERRUPT },
  { SIGINT,	SIGNAL_INTERRUPT },
  { SIGQUIT,	SIGNAL_INTERRUPT },
  { SIGILL,	SIGNAL_FATAL },
  { SIGABRT,	SIGNAL_FATAL },
  { SIGFPE,	SIGNAL_FATAL },
  { SIGSEGV,	SIGNAL_FATAL },
  { SIGPIPE,	SIGNAL_IGNORE },
  { SIGTERM,	SIGNAL_INTERRUPT },
  { SIGUSR1,	SIGNAL_IGNORE },
  { SIGUSR2,	SIGNAL_IGNORE },
  { SIGBUS,	SIGNAL_FATAL },
  { SIGTTOU,	SIGNAL_IGNORE },
};

static void
signal_alarm(int unused UNUSED)
{
  /* Time limit checks are synchronous, so we only schedule them there. */
  timer_tick = 1;
  msg("[timer]");
}

static void
signal_int(int signum)
{
  /* Interrupts (e.g., SIGINT) are synchronous, too. */
  interrupt = signum;
}

static void
signal_fatal(int signum)
{
  /* If we receive SIGSEGV or a similar signal, we try to die gracefully. */
  die("Sandbox keeper received fatal signal %d", signum);
}

static void
setup_signals(void)
{
  struct sigaction sa_int, sa_fatal;
  bzero(&sa_int, sizeof(sa_int));
  sa_int.sa_handler = signal_int;
  bzero(&sa_fatal, sizeof(sa_fatal));
  sa_fatal.sa_handler = signal_fatal;

  for (int i=0; i < ARRAY_SIZE(signal_rules); i++)
    {
      const struct signal_rule *sr = &signal_rules[i];
      switch (sr->action)
	{
	case SIGNAL_IGNORE:
	  signal(sr->signum, SIG_IGN);
	  break;
	case SIGNAL_INTERRUPT:
	  sigaction(sr->signum, &sa_int, NULL);
	  break;
	case SIGNAL_FATAL:
	  sigaction(sr->signum, &sa_fatal, NULL);
	  break;
	default:
	  die("Invalid signal rule");
	}
    }
}

static void
reset_signals(void)
{
  for (int i=0; i < ARRAY_SIZE(signal_rules); i++)
    signal(signal_rules[i].signum, SIG_DFL);
}

/*** The keeper process ***/

#define PROC_BUF_SIZE 4096
static int
read_proc_file(char *buf, char *name, int *fdp)
{
  int c;

  if (*fdp < 0)
    {
      snprintf(buf, PROC_BUF_SIZE, "/proc/%d/%s", (int) box_pid, name);
      *fdp = open(buf, O_RDONLY);
      if (*fdp < 0)
	return 0;	// This is OK, the process could have finished
    }
  lseek(*fdp, 0, SEEK_SET);
  if ((c = read(*fdp, buf, PROC_BUF_SIZE-1)) < 0)
    {
      // Even this could fail if the process disappeared since open()
      return 0;
    }
  if (c >= PROC_BUF_SIZE-1)
    die("/proc/$pid/%s too long", name);
  buf[c] = 0;
  return 1;
}

static int
get_wall_time_ms(void)
{
  struct timespec now, wall;
  clock_gettime(CLOCK_MONOTONIC, &now);
  timespec_sub(&now, &start_time, &wall);
  return wall.tv_sec*1000 + wall.tv_nsec/1000000;
}

static int
get_run_time_ms(struct rusage *rus)
{
  if (cg_enable)
    return cg_get_run_time_ms();

  if (rus)
    {
      struct timeval total;
      timeradd(&rus->ru_utime, &rus->ru_stime, &total);
      return total.tv_sec*1000 + total.tv_usec/1000;
    }

  // It might happen that we do not know the box_pid (see comments in find_box_pid())
  if (!box_pid)
    return 0;

  char buf[PROC_BUF_SIZE], *x;
  int utime, stime;
  static int proc_stat_fd = -1;

  if (!read_proc_file(buf, "stat", &proc_stat_fd))
    return 0;
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

  return (utime + stime) * 1000 / ticks_per_sec;
}

static void
check_timeout(void)
{
  if (wall_timeout)
    {
      int wall_ms = get_wall_time_ms();
      if (wall_ms > wall_timeout)
        err("TO: Time limit exceeded (wall clock)");
      if (verbose > 1)
        fprintf(stderr, "[wall time check: %d msec]\n", wall_ms);
    }
  if (timeout)
    {
      int ms = get_run_time_ms(NULL);
      if (verbose > 1)
	fprintf(stderr, "[time check: %d msec]\n", ms);
      if (ms > timeout && ms > extra_timeout)
	err("TO: Time limit exceeded");
    }
}

static void
box_keeper(void)
{
  read_errors_from_fd = error_pipes[0];
  close(error_pipes[1]);
  close(status_pipes[1]);

  clock_gettime(CLOCK_MONOTONIC, &start_time);
  ticks_per_sec = sysconf(_SC_CLK_TCK);
  if (ticks_per_sec <= 0)
    die("Invalid ticks_per_sec!");

  if (timeout || wall_timeout)
    {
      struct sigaction sa;
      bzero(&sa, sizeof(sa));
      sa.sa_handler = signal_alarm;
      sigaction(SIGALRM, &sa, NULL);
      struct itimerval timer = {
	.it_interval = { .tv_usec = TIMER_INTERVAL_US },
	.it_value = { .tv_usec = TIMER_INTERVAL_US },
      };
      setitimer(ITIMER_REAL, &timer, NULL);
    }

  for(;;)
    {
      struct rusage rus;
      int stat;
      pid_t p;
      if (interrupt)
	{
	  meta_printf("exitsig:%d\n", interrupt);
	  err("SG: Interrupted");
	}
      if (timer_tick)
	{
	  check_timeout();
	  timer_tick = 0;
	}
      p = wait4(proxy_pid, &stat, 0, &rus);
      if (p < 0)
	{
	  if (errno == EINTR)
	    continue;
	  die("wait4: %m");
	}
      if (p != proxy_pid)
	die("wait4: unknown pid %d exited!", p);
      proxy_pid = 0;

      // Check error pipe if there is an internal error passed from inside the box
      char interr[1024];
      int n = read(read_errors_from_fd, interr, sizeof(interr) - 1);
      if (n > 0)
	{
	  interr[n] = 0;
	  die("%s", interr);
	}

      // Check status pipe if there is an exit status reported by the proxy process
      n = read(status_pipes[0], &stat, sizeof(stat));
      if (n != sizeof(stat))
	die("Did not receive exit status from proxy");

      // At this point, the rusage includes time spent by the proxy's children.
      final_stats(&rus);
      if (timeout && total_ms > timeout)
	err("TO: Time limit exceeded");
      if (wall_timeout && wall_ms > wall_timeout)
	err("TO: Time limit exceeded (wall clock)");

      if (WIFEXITED(stat))
	{
	  meta_printf("exitcode:%d\n", WEXITSTATUS(stat));
	  if (WEXITSTATUS(stat))
	    err("RE: Exited with error status %d", WEXITSTATUS(stat));
	  flush_line();
	  if (!silent)
	    {
	      fprintf(stderr, "OK (%d.%03d sec real, %d.%03d sec wall)\n",
		total_ms/1000, total_ms%1000,
		wall_ms/1000, wall_ms%1000);
	    }
	  box_exit(0);
	}
      else if (WIFSIGNALED(stat))
	{
	  meta_printf("exitsig:%d\n", WTERMSIG(stat));
	  err("SG: Caught fatal signal %d", WTERMSIG(stat));
	}
      else if (WIFSTOPPED(stat))
	{
	  meta_printf("exitsig:%d\n", WSTOPSIG(stat));
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
  if (mkdir("root", 0750) < 0 && errno != EEXIST)
    die("mkdir('root'): %m");

  /*
   * Ensure all mounts are private, not shared. We don't want our mounts
   * appearing outside of our namespace.
   * (systemd since version 188 mounts filesystems shared by default).
   */
  if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0)
    die("Cannot privatize mounts: %m");

  if (mount("none", "root", "tmpfs", 0, "mode=755") < 0)
    die("Cannot mount root ramdisk: %m");

  apply_dir_rules(default_dirs);

  if (chroot("root") < 0)
    die("Chroot failed: %m");

  if (chdir("root/box") < 0)
    die("Cannot change current directory: %m");
}

static void
setup_net(void)
{
  if (share_net)
    return;

  int fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    die("Cannot create PF_INET socket: %m");

  struct ifreq ifr = { .ifr_name = "lo" };
  if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
    die("SIOCGIFFLAGS on 'lo' failed: %m");

  ifr.ifr_flags |= IFF_UP;
  if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
    die("SIOCSIFFLAGS on 'lo' failed: %m");

  close(fd);
}

static void
setup_credentials(void)
{
  if (setresgid(box_gid, box_gid, box_gid) < 0)
    die("setresgid: %m");
  if (setgroups(0, NULL) < 0)
    die("setgroups: %m");
  if (setresuid(box_uid, box_uid, box_uid) < 0)
    die("setresuid: %m");
  setpgrp();
  if (tty_hack && isatty(1))
    {
      // If stdout is a tty, make us the foreground process group
      signal(SIGTTOU, SIG_IGN);
      tcsetpgrp(1, getpgrp());
      signal(SIGTTOU, SIG_DFL);
    }
}

static void
setup_fds(void)
{
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
  if (redir_stderr_to_stdout)
    {
      if (dup2(1, 2) < 0)
	die("Cannot dup stdout to stderr: %m");
    }
}

static void
setup_rlim(const char *res_name, int res, rlim_t limit)
{
  struct rlimit rl = { .rlim_cur = limit, .rlim_max = limit };
  if (setrlimit(res, &rl) < 0)
    die("setrlimit(%s, %jd)", res_name, (intmax_t) limit);
}

static void
setup_rlimits(void)
{
#define RLIM(res, val) setup_rlim("RLIMIT_" #res, RLIMIT_##res, val)

  if (memory_limit)
    RLIM(AS, (rlim_t)memory_limit * 1024);

  if (fsize_limit)
    RLIM(FSIZE, (rlim_t)fsize_limit * 1024);

  if (open_file_limit)
    RLIM(NOFILE, (rlim_t)open_file_limit);

  RLIM(STACK, (stack_limit ? (rlim_t)stack_limit * 1024 : RLIM_INFINITY));
  RLIM(MEMLOCK, 0);
  RLIM(CORE, (rlim_t)core_limit * 1024);

  if (max_processes)
    RLIM(NPROC, max_processes);

#undef RLIM
}

static int
box_inside(char **args)
{
  cg_enter();
  setup_root();
  setup_net();
  setup_rlimits();
  setup_credentials();
  setup_fds();
  char **env = setup_environment();

  if (set_cwd && chdir(set_cwd))
    die("chdir: %m");

  execve(args[0], args, env);
  fprintf(stderr, "execve(\"%s\"): %m\n", args[0]);
  exit(127);
}

/*** Proxy ***/

static void
setup_orig_credentials(void)
{
  if (setresgid(orig_gid, orig_gid, orig_gid) < 0)
    die("setresgid: %m");
  if (setgroups(0, NULL) < 0)
    die("setgroups: %m");
  if (setresuid(orig_uid, orig_uid, orig_uid) < 0)
    die("setresuid: %m");
}

static int
box_proxy(void *arg)
{
  char **args = arg;

  write_errors_to_fd = error_pipes[1];
  close(error_pipes[0]);
  close(status_pipes[0]);
  meta_close();
  lock_close();
  reset_signals();

  pid_t inside_pid = fork();
  if (inside_pid < 0)
    die("Cannot run process, fork failed: %m");
  else if (!inside_pid)
    {
      close(status_pipes[1]);
      box_inside(args);
      _exit(42);	// We should never get here
    }

  setup_orig_credentials();
  if (write(status_pipes[1], &inside_pid, sizeof(inside_pid)) != sizeof(inside_pid))
    die("Proxy write to pipe failed: %m");

  int stat;
  pid_t p = waitpid(inside_pid, &stat, 0);
  if (p < 0)
    die("Proxy waitpid() failed: %m");

  if (write(status_pipes[1], &stat, sizeof(stat)) != sizeof(stat))
    die("Proxy write to pipe failed: %m");

  _exit(0);
}

static void
box_init(void)
{
  if (box_id < 0 || box_id >= cf_num_boxes)
    die("Sandbox ID out of range (allowed: 0-%d)", cf_num_boxes-1);
  box_uid = cf_first_uid + box_id;
  box_gid = cf_first_gid + box_id;

  snprintf(box_dir, sizeof(box_dir), "%s/%d", cf_box_root, box_id);
}

/*** Commands ***/

static const char *
self_name(void)
{
  return cg_enable ? "isolate --cg" : "isolate";
}

static void
get_credentials(void)
{
  if (geteuid())
    die("Must be started as root");
  if (getegid() && setegid(0) < 0)
    die("Cannot switch to root group: %m");

  orig_uid = getuid();
  orig_gid = getgid();
  invoked_by_root = !orig_uid;

  if (as_uid >= 0 || as_gid >= 0)
    {
      if (!invoked_by_root)
	die("You must be root to use --as-uid or --as-gid");
      if (as_uid < 0 || as_gid < 0)
	die("--as-uid and --as-gid must be used either both or none");
      orig_uid = as_uid;
      orig_gid = as_gid;
    }
}

static void
do_cleanup(void)
{
  if (dir_exists(box_dir))
    {
      msg("Removing box directory\n");
      rmtree(box_dir);
    }
  cg_remove();
}

static void
init(void)
{
  if (cf_restricted_init && !invoked_by_root)
    die("New sandboxes can be created only by root");

  lock_box(true);

  do_cleanup();

  msg("Preparing sandbox\n");
  make_dir(box_dir);
  if (chdir(box_dir) < 0)
    die("chdir(%s): %m", box_dir);
  if (mkdir("box", 0700) < 0)
    die("Cannot create box: %m");
  if (chown("box", orig_uid, orig_gid) < 0)
    die("Cannot chown box: %m");

  cg_create();
  set_quota();

  lock.is_initialized = 1;
  lock_write();

  puts(box_dir);
}

static void
cleanup(void)
{
  if (!lock_box(false))
    msg("Nothing to do -- box did not exist\n");
  else
    {
      msg("Deleting sandbox\n");
      do_cleanup();
      lock_remove();
    }
}

static void
setup_pipe(int *fds, int nonblocking)
{
  if (pipe(fds) < 0)
    die("pipe: %m");
  for (int i=0; i<2; i++)
    if (fcntl(fds[i], F_SETFD, fcntl(fds[i], F_GETFD) | FD_CLOEXEC) < 0 ||
        nonblocking && fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL) | O_NONBLOCK) < 0)
      die("fcntl on pipe: %m");
}

static void
find_box_pid(void)
{
  /*
   *  The box keeper process wants to poll status of the inside process,
   *  so it needs to know the box_pid. However, it is not easy to obtain:
   *  we got the PID from the proxy, but it is local to the PID namespace.
   *  Instead, we ask /proc to enumerate the children of the proxy.
   *
   *  CAVEAT: The timing is tricky. We know that the inside process was
   *  already started (passing the PID from the proxy to us guarantees it),
   *  but it might already have exited and be reaped by the proxy. Therefore
   *  it is correct if we fail to find anything.
   */

  char namebuf[256];
  snprintf(namebuf, sizeof(namebuf), "/proc/%d/task/%d/children", (int) proxy_pid, (int) proxy_pid);
  FILE *f = fopen(namebuf, "r");
  if (!f)
    return;

  int child;
  if (fscanf(f, "%d", &child) != 1)
    {
      fclose(f);
      return;
    }
  box_pid = child;

  if (fscanf(f, "%d", &child) == 1)
    die("Error parsing %s: unexpected children found", namebuf);

  fclose(f);
}

static void
run(char **argv)
{
  if (!lock_box(false))
    die("Box not found, did you run `%s --init'?", self_name());

  if (chdir(box_dir) < 0)
    die("chdir(%s): %m", box_dir);

  if (!inherit_fds)
    {
      keep_fd(lock_fd);
      close_all_fds();
    }

  chowntree("box", box_uid, box_gid, false);
  cleanup_ownership = 1;

  setup_pipe(error_pipes, 1);
  setup_pipe(status_pipes, 0);
  setup_signals();
  cg_setup();

  proxy_pid = clone(
    box_proxy,			// Function to execute as the body of the new process
    (void*)((uintptr_t)argv & ~(uintptr_t)15),	// Pass our stack, aligned to 16-bytes
    SIGCHLD | CLONE_NEWIPC | (share_net ? 0 : CLONE_NEWNET) | CLONE_NEWNS | CLONE_NEWPID,
    argv);			// Pass the arguments
  if (proxy_pid < 0)
    die("Cannot run proxy, clone failed: %m");
  if (!proxy_pid)
    die("Cannot run proxy, clone returned 0");

  pid_t box_pid_inside_ns;
  int n = read(status_pipes[0], &box_pid_inside_ns, sizeof(box_pid_inside_ns));
  if (n != sizeof(box_pid_inside_ns))
    die("Proxy failed before it passed box_pid: %m");
  find_box_pid();
  msg("Started proxy_pid=%d box_pid=%d box_pid_inside_ns=%d\n", (int) proxy_pid, (int) box_pid, (int) box_pid_inside_ns);

  box_keeper();
}

static void
show_version(void)
{
  printf("The process isolator " ISOLATE_VERSION "\n");
  printf("(c) 2012--" ISOLATE_YEAR " Martin Mares and Bernard Blackham\n");
#if defined(BUILD_DATE) && defined(BUILD_COMMIT)
  printf("Built on " BUILD_DATE " from Git commit " BUILD_COMMIT "\n");
#endif
}

/*** Options ***/

static void __attribute__((format(printf,1,2)))
usage(const char *msg, ...)
{
  if (msg != NULL)
    {
      va_list args;
      va_start(args, msg);
      vfprintf(stderr, msg, args);
      va_end(args);
    }
  printf("\
Usage: isolate [<options>] <command>\n\
\n\
Options:\n\
    --as-uid=<uid>\tPerform action on behalf of a given user (requires root)\n\
    --as-gid=<gid>\tPerform action on behalf of a given group (requires root)\n\
-b, --box-id=<id>\tWhen multiple sandboxes are used in parallel, each must get a unique ID\n\
    --cg\t\tEnable use of control groups\n\
    --cg-mem=<size>\tLimit memory usage of the control group to <size> KB\n\
-c, --chdir=<dir>\tChange directory to <dir> before executing the program\n\
    --core=<size>\tLimit core files to <size> KB (default: 0)\n\
-d, --dir=<dir>\t\tMake a directory <dir> visible inside the sandbox\n\
    --dir=<in>=<out>\tMake a directory <out> outside visible as <in> inside\n\
    --dir=<in>=\t\tDelete a previously defined directory rule (even a default one)\n\
    --dir=...:<opt>\tSpecify options for a rule:\n\
\t\t\t\tdev\tAllow access to block/char devices\n\
\t\t\t\tfs\tMount a filesystem (e.g., --dir=/proc:proc:fs)\n\
\t\t\t\tmaybe\tSkip the rule if <out> does not exist\n\
\t\t\t\tnoexec\tDo not allow execution of binaries\n\
\t\t\t\tnorec\tDo not bind the directory recursively\n\
\t\t\t\trw\tAllow read-write access\n\
\t\t\t\ttmp\tCreate as a temporary directory (implies rw)\n\
-D, --no-default-dirs\tDo not add default directory rules\n\
-f, --fsize=<size>\tMax size (in KB) of files that can be created\n\
-E, --env=<var>\t\tInherit the environment variable <var> from the parent process\n\
-E, --env=<var>=<val>\tSet the environment variable <var> to <val>; unset it if <var> is empty\n\
-x, --extra-time=<time>\tSet extra timeout, before which a timing-out program is not yet killed,\n\
\t\t\tso that its real execution time is reported (seconds, fractions allowed)\n\
-e, --full-env\t\tInherit full environment of the parent process\n\
    --inherit-fds\tInherit all file descriptors of the parent process\n\
-m, --mem=<size>\tLimit address space to <size> KB\n\
-M, --meta=<file>\tOutput process information to <file> (name:value)\n\
-n, --open-files=<max>\tLimit number of open files to <max> (default: 64, 0=unlimited)\n\
-q, --quota=<blk>,<ino>\tSet disk quota to <blk> blocks and <ino> inodes\n\
    --share-net\t\tShare network namespace with the parent process\n\
-s, --silent\t\tDo not print status messages except for fatal errors\n\
    --special-files\tKeep non-regular files (symlinks etc.) produced inside sandbox\n\
-k, --stack=<size>\tLimit stack size to <size> KB (default: 0=unlimited)\n\
-r, --stderr=<file>\tRedirect stderr to <file>\n\
    --stderr-to-stdout\tRedirect stderr to stdout\n\
-i, --stdin=<file>\tRedirect stdin from <file>\n\
-o, --stdout=<file>\tRedirect stdout to <file>\n\
-p, --processes[=<max>]\tEnable multiple processes (at most <max> of them); needs --cg\n\
-t, --time=<time>\tSet run time limit (seconds, fractions allowed)\n\
    --tty-hack\t\tAllow interactive programs in the sandbox (see man for caveats)\n\
-v, --verbose\t\tBe verbose (use multiple times for even more verbosity)\n\
    --wait\t\tIf the sandbox is currently busy, wait instead of refusing to run\n\
-w, --wall-time=<time>\tSet wall clock time limit (seconds, fractions allowed)\n\
\n\
Commands:\n\
    --init\t\tInitialize sandbox (and its control group when --cg is used)\n\
    --run -- <cmd> ...\tRun given command within sandbox\n\
    --cleanup\t\tClean up sandbox\n\
    --print-cg-root\tPrint the root of cgroup hierarchy\n\
    --version\t\tDisplay program version and configuration\n\
");
  exit(2);
}

enum opt_code {
  OPT_INIT = 256,
  OPT_RUN,
  OPT_CLEANUP,
  OPT_VERSION,
  OPT_CG,
  OPT_CG_MEM,
  OPT_SHARE_NET,
  OPT_INHERIT_FDS,
  OPT_STDERR_TO_STDOUT,
  OPT_TTY_HACK,
  OPT_CORE,
  OPT_SPECIAL_FILES,
  OPT_WAIT,
  OPT_AS_UID,
  OPT_AS_GID,
  OPT_PRINT_CG_ROOT,
};

static const char short_opts[] = "b:c:d:DeE:f:i:k:m:M:n:o:p::q:r:st:vw:x:";

static const struct option long_opts[] = {
  { "as-uid",		1, NULL, OPT_AS_UID },
  { "as-gid",		1, NULL, OPT_AS_GID },
  { "box-id",		1, NULL, 'b' },
  { "chdir",		1, NULL, 'c' },
  { "cg",		0, NULL, OPT_CG },
  { "cg-mem",		1, NULL, OPT_CG_MEM },
  { "cleanup",		0, NULL, OPT_CLEANUP },
  { "core",		1, NULL, OPT_CORE },
  { "dir",		1, NULL, 'd' },
  { "no-default-dirs",  0, NULL, 'D' },
  { "fsize",		1, NULL, 'f' },
  { "env",		1, NULL, 'E' },
  { "extra-time",	1, NULL, 'x' },
  { "full-env",		0, NULL, 'e' },
  { "inherit-fds",	0, NULL, OPT_INHERIT_FDS },
  { "init",		0, NULL, OPT_INIT },
  { "mem",		1, NULL, 'm' },
  { "meta",		1, NULL, 'M' },
  { "processes",	2, NULL, 'p' },
  { "quota",		1, NULL, 'q' },
  { "run",		0, NULL, OPT_RUN },
  { "share-net",	0, NULL, OPT_SHARE_NET },
  { "silent",		0, NULL, 's' },
  { "stack",		1, NULL, 'k' },
  { "open-files",	1, NULL, 'n' },
  { "print-cg-root",	0, NULL, OPT_PRINT_CG_ROOT },
  { "special-files",	0, NULL, OPT_SPECIAL_FILES },
  { "stderr",		1, NULL, 'r' },
  { "stderr-to-stdout",	0, NULL, OPT_STDERR_TO_STDOUT },
  { "stdin",		1, NULL, 'i' },
  { "stdout",		1, NULL, 'o' },
  { "time",		1, NULL, 't' },
  { "tty-hack",		0, NULL, OPT_TTY_HACK },
  { "verbose",		0, NULL, 'v' },
  { "version",		0, NULL, OPT_VERSION },
  { "wait",		0, NULL, OPT_WAIT },
  { "wall-time",	1, NULL, 'w' },
  { NULL,		0, NULL, 0 }
};

static unsigned int
opt_uint(char *val)
{
  // This accepts unsigned values which also fit within a signed int
  char *end;
  errno = 0;
  unsigned long int x = strtoul(val, &end, 10);
  if (errno || end == val || end && *end)
    usage("Invalid numeric parameter: %s\n", val);
  if (x > INT_MAX)
    usage("Numeric parameter out of range: %s\n", val);
  return x;
}

int
main(int argc, char **argv)
{
  int c;
  int require_cg = 0;
  char *sep;
  enum opt_code mode = 0;

  init_dir_rules();

  while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) >= 0)
    switch (c)
      {
      case 'b':
	box_id = opt_uint(optarg);
	break;
      case 'c':
	set_cwd = optarg;
	break;
      case OPT_CG:
	cg_enable = 1;
	break;
      case 'd':
	if (!set_dir_action(optarg))
	  usage("Invalid directory rule specified: %s\n", optarg);
	break;
      case 'D':
        default_dirs = 0;
        break;
      case 'e':
	pass_environ = 1;
	break;
      case 'E':
	if (!set_env_action(optarg))
	  usage("Invalid environment specified: %s\n", optarg);
	break;
      case 'f':
        fsize_limit = opt_uint(optarg);
        break;
      case 'k':
	stack_limit = opt_uint(optarg);
	break;
      case 'n':
	open_file_limit = opt_uint(optarg);
	break;
      case 'i':
	redir_stdin = optarg;
	break;
      case 'm':
	memory_limit = opt_uint(optarg);
	break;
      case 'M':
	meta_open(optarg);
	break;
      case 'o':
	redir_stdout = optarg;
	break;
      case 'p':
	if (optarg)
	  max_processes = opt_uint(optarg);
	else
	  max_processes = 0;
	break;
      case 'q':
	optarg = xstrdup(optarg);
	sep = strchr(optarg, ',');
	if (!sep)
	  usage("Invalid quota specified: %s\n", optarg);
	*sep = 0;
	block_quota = opt_uint(optarg);
	inode_quota = opt_uint(sep+1);
	break;
      case 'r':
	redir_stderr = optarg;
	redir_stderr_to_stdout = 0;
	break;
      case 's':
	silent++;
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
      case OPT_INIT:
      case OPT_RUN:
      case OPT_CLEANUP:
      case OPT_VERSION:
      case OPT_PRINT_CG_ROOT:
	if (!mode || (int) mode == c)
	  mode = c;
	else
	  usage("Only one command is allowed.\n");
	break;
      case OPT_CG_MEM:
	cg_memory_limit = opt_uint(optarg);
	require_cg = 1;
	break;
      case OPT_SHARE_NET:
	share_net = 1;
	break;
      case OPT_INHERIT_FDS:
	inherit_fds = 1;
	break;
      case OPT_STDERR_TO_STDOUT:
	redir_stderr = NULL;
	redir_stderr_to_stdout = 1;
	break;
      case OPT_TTY_HACK:
	tty_hack = 1;
	break;
      case OPT_CORE:
	core_limit = opt_uint(optarg);
	break;
      case OPT_SPECIAL_FILES:
	special_files = true;
	break;
      case OPT_WAIT:
	wait_if_busy = true;
	break;
      case OPT_AS_UID:
	as_uid = opt_uint(optarg);
	break;
      case OPT_AS_GID:
	as_gid = opt_uint(optarg);
	break;
      default:
	usage(NULL);
      }

  if (!mode)
    usage("Please specify an isolate command (e.g. --init, --run).\n");
  if (mode == OPT_VERSION)
    {
      show_version();
      return 0;
    }

  if (mode == OPT_PRINT_CG_ROOT)
    cg_enable = 1;

  if (require_cg && !cg_enable)
    usage("Options related to control groups require --cg to be set.\n");

  get_credentials();
  umask(022);
  cf_parse();
  box_init();
  cg_init();

  switch (mode)
    {
    case OPT_INIT:
      if (optind < argc)
	usage("--init mode takes no parameters\n");
      init();
      break;
    case OPT_RUN:
      if (optind >= argc)
	usage("--run mode requires a command to run\n");
      run(argv+optind);
      break;
    case OPT_CLEANUP:
      if (optind < argc)
	usage("--cleanup mode takes no parameters\n");
      cleanup();
      break;
    case OPT_PRINT_CG_ROOT:
      printf("%s\n", cf_cg_root);
      break;
    default:
      die("Internal error: mode mismatch");
    }
  exit(0);
}
