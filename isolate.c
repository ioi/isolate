/*
 *	A Process Isolator based on Linux Containers
 *
 *	(c) 2012-2015 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#define _GNU_SOURCE

#include "config.h"

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
#include <ftw.h>
#include <grp.h>
#include <mntent.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/quota.h>
#include <sys/vfs.h>
#include <sys/fsuid.h>

/* May not be defined in older glibc headers */
#ifndef MS_PRIVATE
#warning "Working around old glibc: no MS_PRIVATE"
#define MS_PRIVATE (1 << 18)
#endif
#ifndef MS_REC
#warning "Working around old glibc: no MS_REC"
#define MS_REC     (1 << 14)
#endif

#define NONRET __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define ARRAY_SIZE(a) (int)(sizeof(a)/sizeof(a[0]))

static int timeout;			/* milliseconds */
static int wall_timeout;
static int extra_timeout;
static int pass_environ;
static int verbose;
static int fsize_limit;
static int memory_limit;
static int stack_limit;
static int block_quota;
static int inode_quota;
static int max_processes = 1;
static char *redir_stdin, *redir_stdout, *redir_stderr;
static char *set_cwd;
static int share_net;

static int cg_enable;
static int cg_memory_limit;
static int cg_timing;

static int box_id;
static char box_dir[1024];
static pid_t box_pid;

static uid_t box_uid;
static gid_t box_gid;
static uid_t orig_uid;
static gid_t orig_gid;

static int partial_line;
static int cleanup_ownership;

static struct timeval start_time;
static int ticks_per_sec;
static int total_ms, wall_ms;
static volatile sig_atomic_t timer_tick;

static int error_pipes[2];
static int write_errors_to_fd;
static int read_errors_from_fd;

static void die(char *msg, ...) NONRET;
static void cg_stats(void);
static int get_wall_time_ms(void);
static int get_run_time_ms(struct rusage *rus);

static void chowntree(char *path, uid_t uid, gid_t gid);

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
  if (setfsuid(getuid()) < 0)
    die("Failed to switch FS UID: %m");
  metafile = fopen(name, "w");
  if (setfsuid(geteuid()) < 0)
    die("Failed to switch FS UID back: %m");
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
  total_ms = get_run_time_ms(rus);
  wall_ms = get_wall_time_ms();

  meta_printf("time:%d.%03d\n", total_ms/1000, total_ms%1000);
  meta_printf("time-wall:%d.%03d\n", wall_ms/1000, wall_ms%1000);
  meta_printf("max-rss:%ld\n", rus->ru_maxrss);
  meta_printf("csw-voluntary:%ld\n", rus->ru_nvcsw);
  meta_printf("csw-forced:%ld\n", rus->ru_nivcsw);

  cg_stats();
}

/*** Messages and exits ***/

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

  if (rc < 2 && cleanup_ownership)
    chowntree("box", orig_uid, orig_gid);

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
  char buf[1024];
  int n = vsnprintf(buf, sizeof(buf), msg, args);

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

/*** Utility functions ***/

static void *
xmalloc(size_t size)
{
  void *p = malloc(size);
  if (!p)
    die("Out of memory");
  return p;
}

static char *
xstrdup(char *str)
{
  char *p = strdup(str);
  if (!p)
    die("Out of memory");
  return p;
}

static int dir_exists(char *path)
{
  struct stat st;
  return (stat(path, &st) >= 0 && S_ISDIR(st.st_mode));
}

static int rmtree_helper(const char *fpath, const struct stat *sb,
    int typeflag UNUSED, struct FTW *ftwbuf UNUSED)
{
  if (S_ISDIR(sb->st_mode))
    {
      if (rmdir(fpath) < 0)
	die("Cannot rmdir %s: %m", fpath);
    }
  else
    {
      if (unlink(fpath) < 0)
	die("Cannot unlink %s: %m", fpath);
    }
  return FTW_CONTINUE;
}

static void
rmtree(char *path)
{
  nftw(path, rmtree_helper, 32, FTW_MOUNT | FTW_PHYS | FTW_DEPTH);
}

static uid_t chown_uid;
static gid_t chown_gid;

static int chowntree_helper(const char *fpath, const struct stat *sb UNUSED,
    int typeflag UNUSED, struct FTW *ftwbuf UNUSED)
{
  if (lchown(fpath, chown_uid, chown_gid) < 0)
    die("Cannot chown %s: %m", fpath);
  else
    return FTW_CONTINUE;
}

static void
chowntree(char *path, uid_t uid, gid_t gid)
{
  chown_uid = uid;
  chown_gid = gid;
  nftw(path, chowntree_helper, 32, FTW_MOUNT | FTW_PHYS);
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

/*** Directory rules ***/

struct dir_rule {
  char *inside;			// A relative path
  char *outside;		// This can be an absolute path or a relative path starting with "./"
  unsigned int flags;		// DIR_FLAG_xxx
  struct dir_rule *next;
};

enum dir_rule_flags {
  DIR_FLAG_RW = 1,
  DIR_FLAG_NOEXEC = 2,
  DIR_FLAG_FS = 4,
  DIR_FLAG_MAYBE = 8,
  DIR_FLAG_DEV = 16,
};

static const char * const dir_flag_names[] = { "rw", "noexec", "fs", "maybe", "dev" };

static struct dir_rule *first_dir_rule;
static struct dir_rule **last_dir_rule = &first_dir_rule;

static int add_dir_rule(char *in, char *out, unsigned int flags)
{
  // Make sure that "in" is relative
  while (in[0] == '/')
    in++;
  if (!*in)
    return 0;

  // Check "out"
  if (flags & DIR_FLAG_FS)
    {
      if (!out || out[0] == '/')
	return 0;
    }
  else
    {
      if (out && out[0] != '/' && strncmp(out, "./", 2))
	return 0;
    }

  // Override an existing rule
  struct dir_rule *r;
  for (r = first_dir_rule; r; r = r->next)
    if (!strcmp(r->inside, in))
      break;

  // Add a new rule
  if (!r)
    {
      r = xmalloc(sizeof(*r));
      r->inside = in;
      *last_dir_rule = r;
      last_dir_rule = &r->next;
      r->next = NULL;
    }
  r->outside = out;
  r->flags = flags;
  return 1;
}

static unsigned int parse_dir_option(char *opt)
{
  for (unsigned int i = 0; i < ARRAY_SIZE(dir_flag_names); i++)
    if (!strcmp(opt, dir_flag_names[i]))
      return 1U << i;
  die("Unknown directory option %s", opt);
}

static int set_dir_action(char *arg)
{
  arg = xstrdup(arg);

  char *colon = strchr(arg, ':');
  unsigned int flags = 0;
  while (colon)
    {
      *colon++ = 0;
      char *next = strchr(colon, ':');
      if (next)
	*next = 0;
      flags |= parse_dir_option(colon);
      colon = next;
    }

  char *eq = strchr(arg, '=');
  if (eq)
    {
      *eq++ = 0;
      return add_dir_rule(arg, (*eq ? eq : NULL), flags);
    }
  else
    {
      char *out = xmalloc(1 + strlen(arg) + 1);
      sprintf(out, "/%s", arg);
      return add_dir_rule(arg, out, flags);
    }
}

static void init_dir_rules(void)
{
  set_dir_action("box=./box:rw");
  set_dir_action("bin");
  set_dir_action("dev:dev");
  set_dir_action("lib");
  set_dir_action("lib64:maybe");
  set_dir_action("proc=proc:fs");
  set_dir_action("usr");
}

static void make_dir(char *path)
{
  char *sep = (path[0] == '/' ? path+1 : path);

  for (;;)
    {
      sep = strchr(sep, '/');
      if (sep)
	*sep = 0;

      if (mkdir(path, 0777) < 0 && (errno != EEXIST || !dir_exists(path)))
	die("Cannot create directory %s: %m\n", path);

      if (!sep)
	return;
      *sep++ = '/';
    }
}

static void apply_dir_rules(void)
{
  for (struct dir_rule *r = first_dir_rule; r; r=r->next)
    {
      char *in = r->inside;
      char *out = r->outside;
      if (!out)
	{
	  msg("Not binding anything on %s\n", r->inside);
	  continue;
	}

      if ((r->flags & DIR_FLAG_MAYBE) && !dir_exists(out))
	{
	  msg("Not binding %s on %s (does not exist)\n", out, r->inside);
	  continue;
	}

      char root_in[1024];
      snprintf(root_in, sizeof(root_in), "root/%s", in);
      make_dir(root_in);

      unsigned long mount_flags = 0;
      if (!(r->flags & DIR_FLAG_RW))
	mount_flags |= MS_RDONLY;
      if (r->flags & DIR_FLAG_NOEXEC)
	mount_flags |= MS_NOEXEC;
      if (!(r->flags & DIR_FLAG_DEV))
	mount_flags |= MS_NODEV;

      if (r->flags & DIR_FLAG_FS)
	{
	  msg("Mounting %s on %s (flags %lx)\n", out, in, mount_flags);
	  if (mount("none", root_in, out, mount_flags, "") < 0)
	    die("Cannot mount %s on %s: %m", out, in);
	}
      else
	{
	  mount_flags |= MS_BIND | MS_NOSUID;
	  msg("Binding %s on %s (flags %lx)\n", out, in, mount_flags);
	  // Most mount flags need remount to work
	  if (mount(out, root_in, "none", mount_flags, "") < 0 ||
	      mount(out, root_in, "none", MS_REMOUNT | mount_flags, "") < 0)
	    die("Cannot mount %s on %s: %m", out, in);
	}
    }
}

/*** Control groups ***/

struct cg_controller_desc {
  const char *name;
  int optional;
};

typedef enum {
  CG_MEMORY = 0,
  CG_CPUACCT,
  CG_CPUSET,
  CG_NUM_CONTROLLERS,
} cg_controller;

static const struct cg_controller_desc cg_controllers[CG_NUM_CONTROLLERS+1] = {
  [CG_MEMORY]  = { "memory",  0 },
  [CG_CPUACCT] = { "cpuacct", 0 },
  [CG_CPUSET]  = { "cpuset",  1 },
  [CG_NUM_CONTROLLERS] = { NULL, 0 },
};

#define FOREACH_CG_CONTROLLER(_controller) \
  for (cg_controller (_controller) = 0; \
       (_controller) < CG_NUM_CONTROLLERS; (_controller)++)

static const char *cg_controller_name(cg_controller c)
{
  return cg_controllers[c].name;
}

static int cg_controller_optional(cg_controller c)
{
  return cg_controllers[c].optional;
}

static char cg_name[256];

#define CG_BUFSIZE 1024

static void
cg_makepath(char *buf, size_t len, cg_controller c, const char *attr)
{
  const char *cg_root = CONFIG_ISOLATE_CGROUP_ROOT;
  snprintf(buf, len, "%s/%s/%s/%s", cg_root, cg_controller_name(c), cg_name, attr);
}

static int
cg_read(cg_controller controller, const char *attr, char *buf)
{
  int result = 0;
  int maybe = 0;
  if (attr[0] == '?')
    {
      attr++;
      maybe = 1;
    }

  char path[256];
  cg_makepath(path, sizeof(path), controller, attr);

  int fd = open(path, O_RDONLY);
  if (fd < 0)
    {
      if (maybe)
	goto fail;
      die("Cannot read %s: %m", path);
    }

  int n = read(fd, buf, CG_BUFSIZE);
  if (n < 0)
    {
      if (maybe)
	goto fail_close;
      die("Cannot read %s: %m", path);
    }
  if (n >= CG_BUFSIZE - 1)
    die("Attribute %s too long", path);
  if (n > 0 && buf[n-1] == '\n')
    n--;
  buf[n] = 0;

  if (verbose > 1)
    msg("CG: Read %s = %s\n", attr, buf);

  result = 1;
fail_close:
  close(fd);
fail:
  return result;
}

static void __attribute__((format(printf,3,4)))
cg_write(cg_controller controller, const char *attr, const char *fmt, ...)
{
  int maybe = 0;
  if (attr[0] == '?')
    {
      attr++;
      maybe = 1;
    }

  va_list args;
  va_start(args, fmt);

  char buf[CG_BUFSIZE];
  int n = vsnprintf(buf, sizeof(buf), fmt, args);
  if (n >= CG_BUFSIZE)
    die("cg_write: Value for attribute %s is too long", attr);

  if (verbose > 1)
    msg("CG: Write %s = %s", attr, buf);

  char path[256];
  cg_makepath(path, sizeof(path), controller, attr);

  int fd = open(path, O_WRONLY | O_TRUNC);
  if (fd < 0)
    {
      if (maybe)
	goto fail;
      else
	die("Cannot write %s: %m", path);
    }

  int written = write(fd, buf, n);
  if (written < 0)
    {
      if (maybe)
	goto fail_close;
      else
	die("Cannot set %s to %s: %m", path, buf);
    }
  if (written != n)
    die("Short write to %s (%d out of %d bytes)", path, written, n);

fail_close:
  close(fd);
fail:
  va_end(args);
}

static void
cg_init(void)
{
  if (!cg_enable)
    return;

  char *cg_root = CONFIG_ISOLATE_CGROUP_ROOT;
  if (!dir_exists(cg_root))
    die("Control group filesystem at %s not mounted", cg_root);

  snprintf(cg_name, sizeof(cg_name), "box-%d", box_id);
  msg("Using control group %s\n", cg_name);
}

static void
cg_prepare(void)
{
  if (!cg_enable)
    return;

  struct stat st;
  char buf[CG_BUFSIZE];
  char path[256];

  FOREACH_CG_CONTROLLER(controller)
    {
      cg_makepath(path, sizeof(path), controller, "");
      if (stat(path, &st) >= 0 || errno != ENOENT)
	{
	  msg("Control group %s already exists, trying to empty it.\n", path);
	  if (rmdir(path) < 0)
	    die("Failed to reset control group %s: %m", path);
	}

      if (mkdir(path, 0777) < 0 && !cg_controller_optional(controller))
	die("Failed to create control group %s: %m", path);
    }

  // If cpuset module is enabled, copy allowed cpus and memory nodes from parent group
  if (cg_read(CG_CPUSET, "?cpuset.cpus", buf))
    cg_write(CG_CPUSET, "cpuset.cpus", "%s", buf);
  if (cg_read(CG_CPUSET, "?cpuset.mems", buf))
    cg_write(CG_CPUSET, "cpuset.mems", "%s", buf);
}

static void
cg_enter(void)
{
  if (!cg_enable)
    return;

  msg("Entering control group %s\n", cg_name);

  FOREACH_CG_CONTROLLER(controller)
    {
      if (cg_controller_optional(controller))
	cg_write(controller, "?tasks", "%d\n", (int) getpid());
      else
	cg_write(controller, "tasks", "%d\n", (int) getpid());
    }

  if (cg_memory_limit)
    {
      cg_write(CG_MEMORY, "memory.limit_in_bytes", "%lld\n", (long long) cg_memory_limit << 10);
      cg_write(CG_MEMORY, "?memory.memsw.limit_in_bytes", "%lld\n", (long long) cg_memory_limit << 10);
    }

  if (cg_timing)
    cg_write(CG_CPUACCT, "cpuacct.usage", "0\n");
}

static int
cg_get_run_time_ms(void)
{
  if (!cg_enable)
    return 0;

  char buf[CG_BUFSIZE];
  cg_read(CG_CPUACCT, "cpuacct.usage", buf);
  unsigned long long ns = atoll(buf);
  return ns / 1000000;
}

static void
cg_stats(void)
{
  if (!cg_enable)
    return;

  char buf[CG_BUFSIZE];

  // Memory usage statistics
  unsigned long long mem=0, memsw=0;
  if (cg_read(CG_MEMORY, "?memory.max_usage_in_bytes", buf))
    mem = atoll(buf);
  if (cg_read(CG_MEMORY, "?memory.memsw.max_usage_in_bytes", buf))
    {
      memsw = atoll(buf);
      if (memsw > mem)
	mem = memsw;
    }
  if (mem)
    meta_printf("cg-mem:%lld\n", mem >> 10);
}

static void
cg_remove(void)
{
  char buf[CG_BUFSIZE];

  if (!cg_enable)
    return;

  FOREACH_CG_CONTROLLER(controller)
    {
      if (cg_controller_optional(controller))
	{
	  if (!cg_read(controller, "?tasks", buf))
	    continue;
	}
      else
	cg_read(controller, "tasks", buf);

      if (buf[0])
	die("Some tasks left in controller %s of cgroup %s, failed to remove it",
	    cg_controller_name(controller), cg_name);

      char path[256];
      cg_makepath(path, sizeof(path), controller, "");

      if (rmdir(path) < 0)
	die("Cannot remove control group %s: %m", path);
    }
}

/*** Disk quotas ***/

static int
path_begins_with(char *path, char *with)
{
  while (*with)
    if (*path++ != *with++)
      return 0;
  return (!*with || *with == '/');
}

static char *
find_device(char *path)
{
  FILE *f = setmntent("/proc/mounts", "r");
  if (!f)
    die("Cannot open /proc/mounts: %m");

  struct mntent *me;
  int best_len = 0;
  char *best_dev = NULL;
  while (me = getmntent(f))
    {
      if (!path_begins_with(me->mnt_fsname, "/dev"))
	continue;
      if (path_begins_with(path, me->mnt_dir))
	{
	  int len = strlen(me->mnt_dir);
	  if (len > best_len)
	    {
	      best_len = len;
	      free(best_dev);
	      best_dev = xstrdup(me->mnt_fsname);
	    }
	}
    }
  endmntent(f);
  return best_dev;
}

static void
set_quota(void)
{
  if (!block_quota)
    return;

  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof(cwd)))
    die("getcwd: %m");

  char *dev = find_device(cwd);
  if (!dev)
    die("Cannot identify filesystem which contains %s", cwd);
  msg("Quota: Mapped path %s to a filesystem on %s\n", cwd, dev);

  // Sanity check
  struct stat dev_st, cwd_st;
  if (stat(dev, &dev_st) < 0)
    die("Cannot identify block device %s: %m", dev);
  if (!S_ISBLK(dev_st.st_mode))
    die("Expected that %s is a block device", dev);
  if (stat(".", &cwd_st) < 0)
    die("Cannot stat cwd: %m");
  if (cwd_st.st_dev != dev_st.st_rdev)
    die("Identified %s as a filesystem on %s, but it is obviously false", cwd, dev);

  struct dqblk dq = {
    .dqb_bhardlimit = block_quota,
    .dqb_bsoftlimit = block_quota,
    .dqb_ihardlimit = inode_quota,
    .dqb_isoftlimit = inode_quota,
    .dqb_valid = QIF_LIMITS,
  };
  if (quotactl(QCMD(Q_SETQUOTA, USRQUOTA), dev, box_uid, (caddr_t) &dq) < 0)
    die("Cannot set disk quota: %m");
  msg("Quota: Set block quota %d and inode quota %d\n", block_quota, inode_quota);

  free(dev);
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
signal_int(int signum)
{
  /* Interrupts are fatal, so no synchronization requirements. */
  meta_printf("exitsig:%d\n", signum);
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

static int
get_wall_time_ms(void)
{
  struct timeval now, wall;
  gettimeofday(&now, NULL);
  timersub(&now, &start_time, &wall);
  return wall.tv_sec*1000 + wall.tv_usec/1000;
}

static int
get_run_time_ms(struct rusage *rus)
{
  if (cg_timing)
    return cg_get_run_time_ms();

  if (rus)
    {
      struct timeval total;
      timeradd(&rus->ru_utime, &rus->ru_stime, &total);
      return total.tv_sec*1000 + total.tv_usec/1000;
    }

  char buf[PROC_BUF_SIZE], *x;
  int utime, stime;
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

  struct sigaction sa;
  bzero(&sa, sizeof(sa));
  sa.sa_handler = signal_int;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGUSR1, &sa, NULL);
  sigaction(SIGUSR2, &sa, NULL);

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
      box_pid = 0;

      // Check error pipe if there is an internal error passed from inside the box
      char interr[1024];
      int n = read(read_errors_from_fd, interr, sizeof(interr) - 1);
      if (n > 0)
	{
	  interr[n] = 0;
	  die("%s", interr);
	}

      if (WIFEXITED(stat))
	{
	  final_stats(&rus);
	  if (WEXITSTATUS(stat))
	    {
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
      else if (WIFSIGNALED(stat))
	{
	  meta_printf("exitsig:%d\n", WTERMSIG(stat));
	  final_stats(&rus);
	  err("SG: Caught fatal signal %d", WTERMSIG(stat));
	}
      else if (WIFSTOPPED(stat))
	{
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

  apply_dir_rules();

  if (chroot("root") < 0)
    die("Chroot failed: %m");

  if (chdir("root/box") < 0)
    die("Cannot change current directory: %m");
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
  else
    dup2(1, 2);
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

  RLIM(STACK, (stack_limit ? (rlim_t)stack_limit * 1024 : RLIM_INFINITY));
  RLIM(NOFILE, 64);
  RLIM(MEMLOCK, 0);

  if (max_processes)
    RLIM(NPROC, max_processes);

#undef RLIM
}

static int
box_inside(void *arg)
{
  char **args = arg;
  write_errors_to_fd = error_pipes[1];
  close(error_pipes[0]);
  meta_close();

  cg_enter();
  setup_root();
  setup_credentials();
  setup_fds();
  setup_rlimits();
  char **env = setup_environment();

  if (set_cwd && chdir(set_cwd))
    die("chdir: %m");

  execve(args[0], args, env);
  die("execve(\"%s\"): %m", args[0]);
}

static void
box_init(void)
{
  if (box_id < 0 || box_id >= CONFIG_ISOLATE_NUM_BOXES)
    die("Sandbox ID out of range (allowed: 0-%d)", CONFIG_ISOLATE_NUM_BOXES-1);
  box_uid = CONFIG_ISOLATE_FIRST_UID + box_id;
  box_gid = CONFIG_ISOLATE_FIRST_GID + box_id;

  snprintf(box_dir, sizeof(box_dir), "%s/%d", CONFIG_ISOLATE_BOX_DIR, box_id);
  make_dir(box_dir);
  if (chdir(box_dir) < 0)
    die("chdir(%s): %m", box_dir);
}

/*** Commands ***/

static void
init(void)
{
  msg("Preparing sandbox directory\n");
  rmtree("box");
  if (mkdir("box", 0700) < 0)
    die("Cannot create box: %m");
  if (chown("box", orig_uid, orig_gid) < 0)
    die("Cannot chown box: %m");

  cg_prepare();
  set_quota();

  puts(box_dir);
}

static void
cleanup(void)
{
  if (!dir_exists("box"))
    die("Box directory not found, there isn't anything to clean up");

  msg("Deleting sandbox directory\n");
  rmtree(box_dir);
  cg_remove();
}

static void
run(char **argv)
{
  if (!dir_exists("box"))
    die("Box directory not found, did you run `isolate --init'?");

  chowntree("box", box_uid, box_gid);
  cleanup_ownership = 1;

  if (pipe(error_pipes) < 0)
    die("pipe: %m");
  for (int i=0; i<2; i++)
    if (fcntl(error_pipes[i], F_SETFD, fcntl(error_pipes[i], F_GETFD) | FD_CLOEXEC) < 0 ||
        fcntl(error_pipes[i], F_SETFL, fcntl(error_pipes[i], F_GETFL) | O_NONBLOCK) < 0)
      die("fcntl on pipe: %m");

  box_pid = clone(
    box_inside,			// Function to execute as the body of the new process
    argv,			// Pass our stack
    SIGCHLD | CLONE_NEWIPC | (share_net ? 0 : CLONE_NEWNET) | CLONE_NEWNS | CLONE_NEWPID,
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
  printf("The process isolator " VERSION "\n");
  printf("(c) 2012--" YEAR " Martin Mares and Bernard Blackham\n");
  printf("Built on " BUILD_DATE " from Git commit " BUILD_COMMIT "\n");
  printf("\nCompile-time configuration:\n");
  printf("Sandbox directory: %s\n", CONFIG_ISOLATE_BOX_DIR);
  printf("Sandbox credentials: uid=%u-%u gid=%u-%u\n",
    CONFIG_ISOLATE_FIRST_UID,
    CONFIG_ISOLATE_FIRST_UID + CONFIG_ISOLATE_NUM_BOXES - 1,
    CONFIG_ISOLATE_FIRST_GID,
    CONFIG_ISOLATE_FIRST_GID + CONFIG_ISOLATE_NUM_BOXES - 1);
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
-b, --box-id=<id>\tWhen multiple sandboxes are used in parallel, each must get a unique ID\n\
    --cg\t\tEnable use of control groups\n\
    --cg-mem=<size>\tLimit memory usage of the control group to <size> KB\n\
    --cg-timing\t\tTime limits affects total run time of the control group\n\
-c, --chdir=<dir>\tChange directory to <dir> before executing the program\n\
-d, --dir=<dir>\t\tMake a directory <dir> visible inside the sandbox\n\
    --dir=<in>=<out>\tMake a directory <out> outside visible as <in> inside\n\
    --dir=<in>=\t\tDelete a previously defined directory rule (even a default one)\n\
    --dir=...:<opt>\tSpecify options for a rule:\n\
\t\t\t\tdev\tAllow access to special files\n\
\t\t\t\tfs\tMount a filesystem (e.g., --dir=/proc:proc:fs)\n\
\t\t\t\tmaybe\tSkip the rule if <out> does not exist\n\
\t\t\t\tnoexec\tDo not allow execution of binaries\n\
\t\t\t\trw\tAllow read-write access\n\
-f, --fsize=<size>\tMax size (in KB) of files that can be created\n\
-E, --env=<var>\t\tInherit the environment variable <var> from the parent process\n\
-E, --env=<var>=<val>\tSet the environment variable <var> to <val>; unset it if <var> is empty\n\
-x, --extra-time=<time>\tSet extra timeout, before which a timing-out program is not yet killed,\n\
\t\t\tso that its real execution time is reported (seconds, fractions allowed)\n\
-e, --full-env\t\tInherit full environment of the parent process\n\
-m, --mem=<size>\tLimit address space to <size> KB\n\
-M, --meta=<file>\tOutput process information to <file> (name:value)\n\
-q, --quota=<blk>,<ino>\tSet disk quota to <blk> blocks and <ino> inodes\n\
    --share-net\t\tShare network namespace with the parent process\n\
-k, --stack=<size>\tLimit stack size to <size> KB (default: 0=unlimited)\n\
-r, --stderr=<file>\tRedirect stderr to <file>\n\
-i, --stdin=<file>\tRedirect stdin from <file>\n\
-o, --stdout=<file>\tRedirect stdout to <file>\n\
-p, --processes[=<max>]\tEnable multiple processes (at most <max> of them); needs --cg\n\
-t, --time=<time>\tSet run time limit (seconds, fractions allowed)\n\
-v, --verbose\t\tBe verbose (use multiple times for even more verbosity)\n\
-w, --wall-time=<time>\tSet wall clock time limit (seconds, fractions allowed)\n\
\n\
Commands:\n\
    --init\t\tInitialize sandbox (and its control group when --cg is used)\n\
    --run -- <cmd> ...\tRun given command within sandbox\n\
    --cleanup\t\tClean up sandbox\n\
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
  OPT_CG_TIMING,
  OPT_SHARE_NET,
};

static const char short_opts[] = "b:c:d:eE:i:k:m:M:o:p::q:r:t:vw:x:";

static const struct option long_opts[] = {
  { "box-id",		1, NULL, 'b' },
  { "chdir",		1, NULL, 'c' },
  { "cg",		0, NULL, OPT_CG },
  { "cg-mem",		1, NULL, OPT_CG_MEM },
  { "cg-timing",	0, NULL, OPT_CG_TIMING },
  { "cleanup",		0, NULL, OPT_CLEANUP },
  { "dir",		1, NULL, 'd' },
  { "fsize",		1, NULL, 'f' },
  { "env",		1, NULL, 'E' },
  { "extra-time",	1, NULL, 'x' },
  { "full-env",		0, NULL, 'e' },
  { "init",		0, NULL, OPT_INIT },
  { "mem",		1, NULL, 'm' },
  { "meta",		1, NULL, 'M' },
  { "processes",	2, NULL, 'p' },
  { "quota",		1, NULL, 'q' },
  { "run",		0, NULL, OPT_RUN },
  { "share-net",	0, NULL, OPT_SHARE_NET },
  { "stack",		1, NULL, 'k' },
  { "stderr",		1, NULL, 'r' },
  { "stdin",		1, NULL, 'i' },
  { "stdout",		1, NULL, 'o' },
  { "time",		1, NULL, 't' },
  { "verbose",		0, NULL, 'v' },
  { "version",		0, NULL, OPT_VERSION },
  { "wall-time",	1, NULL, 'w' },
  { NULL,		0, NULL, 0 }
};

int
main(int argc, char **argv)
{
  int c;
  char *sep;
  enum opt_code mode = 0;

  init_dir_rules();

  while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) >= 0)
    switch (c)
      {
      case 'b':
	box_id = atoi(optarg);
	break;
      case 'c':
	set_cwd = optarg;
	break;
      case OPT_CG:
	cg_enable = 1;
	break;
      case 'd':
	if (!set_dir_action(optarg))
	  usage("Invalid directory specified: %s\n", optarg);
	break;
      case 'f':
        fsize_limit = atoi(optarg);
        break;
      case 'e':
	pass_environ = 1;
	break;
      case 'E':
	if (!set_env_action(optarg))
	  usage("Invalid environment specified: %s\n", optarg);
	break;
      case 'k':
	stack_limit = atoi(optarg);
	break;
      case 'i':
	redir_stdin = optarg;
	break;
      case 'm':
	memory_limit = atoi(optarg);
	break;
      case 'M':
	meta_open(optarg);
	break;
      case 'o':
	redir_stdout = optarg;
	break;
      case 'p':
	if (optarg)
	  max_processes = atoi(optarg);
	else
	  max_processes = 0;
	break;
      case 'q':
	sep = strchr(optarg, ',');
	if (!sep)
	  usage("Invalid quota specified: %s\n", optarg);
	block_quota = atoi(optarg);
	inode_quota = atoi(sep+1);
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
      case OPT_INIT:
      case OPT_RUN:
      case OPT_CLEANUP:
      case OPT_VERSION:
	if (!mode || (int) mode == c)
	  mode = c;
	else
	  usage("Only one command is allowed.\n");
	break;
      case OPT_CG_MEM:
	cg_memory_limit = atoi(optarg);
	break;
      case OPT_CG_TIMING:
	cg_timing = 1;
	break;
      case OPT_SHARE_NET:
	share_net = 1;
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

  if (geteuid())
    die("Must be started as root");
  orig_uid = getuid();
  orig_gid = getgid();

  umask(022);
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
    default:
      die("Internal error: mode mismatch");
    }
  exit(0);
}
