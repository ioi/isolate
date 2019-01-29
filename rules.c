/*
 *	Process Isolator -- Rules
 *
 *	(c) 2012-2018 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <limits.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/quota.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

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
  { .var = "LIBC_FATAL_STDERR_", .val = "1", .var_len = 18 },
};

int
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

char **
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
  DIR_FLAG_TMP = 32,
  DIR_FLAG_NOREC = 64,
  DIR_FLAG_DEFAULT = 1U << 15,	// Used internally
  DIR_FLAG_DISABLED = 1U << 16,	// Used internally
};

static const char * const dir_flag_names[] = { "rw", "noexec", "fs", "maybe", "dev", "tmp", "norec" };

static struct dir_rule *first_dir_rule;
static struct dir_rule **last_dir_rule = &first_dir_rule;

static char *
sanitize_dir_path(char *path)
{
  // Strip leading slashes
  while (*path == '/')
    path++;
  if (!*path)
    return NULL;

  // Check for ".." components
  char *p = path;
  while (*p)
    {
      char *next = strchr(p, '/');
      if (!next)
	next = p + strlen(p);

      int len = next - p;
      if (len == 2 && !memcmp(p, "..", 2))
	return NULL;

      p = *next ? next+1 : next;
    }

  return path;
}

static int
add_dir_rule(char *in, char *out, unsigned int flags)
{
  // Make sure that "in" does not try to escape the box
  in = sanitize_dir_path(in);
  if (!in)
    return 0;

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

static unsigned int
parse_dir_option(char *opt)
{
  for (unsigned int i = 0; i < ARRAY_SIZE(dir_flag_names); i++)
    if (!strcmp(opt, dir_flag_names[i]))
      return 1U << i;
  die("Unknown directory option %s", opt);
}

static int
set_dir_action_ext(char *arg, unsigned int ext_flags)
{
  arg = xstrdup(arg);

  char *colon = strchr(arg, ':');
  unsigned int flags = ext_flags;
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
    *eq++ = 0;

  if ((flags & DIR_FLAG_FS) && (flags & DIR_FLAG_TMP))
    return 0;

  if (flags & DIR_FLAG_FS)
    {
      if (!eq || strchr(eq, '/'))
	return 0;
      return add_dir_rule(arg, eq, flags);
    }
  else if (flags & DIR_FLAG_TMP)
    {
      if (eq)
	return 0;
      /*
       *  Construct an outside temporary directory, which will be later
       *  chowned to box_uid. The hierarchy of these directories is intentionally
       *  flat, so that we avoid writing to a directory which might have already
       *  tampered with in a previous run of the sandbox.
       */
      char out[1024];
      snprintf(out, sizeof(out), "./tmp/%s", arg);
      for (char *p = out + strlen("./tmp/"); *p; p++)
	if (*p == '/')
	  *p = ':';		// This is safe, there were no colons in "out"
      return add_dir_rule(arg, xstrdup(out), flags | DIR_FLAG_RW);
    }
  else if (eq)
    {
      if (!eq[0])
	return add_dir_rule(arg, NULL, flags);
      if (eq[0] != '/' && strncmp(eq, "./", 2))
	return 0;
      return add_dir_rule(arg, eq, flags);
    }
  else
    {
      char *out = xmalloc(1 + strlen(arg) + 1);
      sprintf(out, "/%s", arg);
      return add_dir_rule(arg, out, flags);
    }
}

int
set_dir_action(char *arg)
{
  return set_dir_action_ext(arg, 0);
}

static int
set_dir_action_default(char *arg)
{
  return set_dir_action_ext(arg, DIR_FLAG_DEFAULT);
}

void
init_dir_rules(void)
{
  set_dir_action_default("box=./box:rw");
  set_dir_action_default("bin");
  set_dir_action_default("dev:dev");
  set_dir_action_default("lib");
  set_dir_action_default("lib64:maybe");
  set_dir_action_default("proc=proc:fs");
  set_dir_action_default("tmp:tmp");
  set_dir_action_default("usr");
}

static void
set_cap_sys_admin(void)
{
  cap_t caps;
  if (!(caps = cap_get_proc()))
    die("Cannot get capabilities: %m");

  cap_value_t cap_list[] = { CAP_SYS_ADMIN };
  if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) < 0)
    die("Cannot modify capabilities");

  if (cap_set_proc(caps) < 0)
    die("Cannot set capabilities: %m");

  cap_free(caps);
}

void
apply_dir_rules(int with_defaults)
{
  /*
   * Before mounting anything, we create all mount points inside the box.
   * This is necessary to avoid bypassing directory permissions. If you
   * want nested binds, you have to create the mount points explicitly.
   */
  for (struct dir_rule *r = first_dir_rule; r; r=r->next)
    {
      if (!with_defaults && (r->flags & DIR_FLAG_DEFAULT))
        continue;

      char *in = r->inside;
      char *out = r->outside;

      if (!out)
	{
	  msg("Not binding anything on %s\n", in);
	  r->flags |= DIR_FLAG_DISABLED;
	  continue;
	}

      if ((r->flags & DIR_FLAG_MAYBE) && !dir_exists(out))
	{
	  msg("Not binding %s on %s (does not exist)\n", out, r->inside);
	  r->flags |= DIR_FLAG_DISABLED;
	  continue;
	}

      char root_in[1024];
      snprintf(root_in, sizeof(root_in), "root/%s", in);
      make_dir(root_in);
    }

  for (struct dir_rule *r = first_dir_rule; r; r=r->next)
    {
      if (r->flags & DIR_FLAG_DISABLED)
	continue;
      if (!with_defaults && (r->flags & DIR_FLAG_DEFAULT))
        continue;

      char *in = r->inside;
      char *out = r->outside;
      char root_in[1024];
      snprintf(root_in, sizeof(root_in), "root/%s", in);

      if (r->flags & DIR_FLAG_TMP)
	{
	  make_dir(out);
	  if (chown(out, box_uid, box_gid) < 0)
	    die("Cannot chown %s: %m", out);
	  if (chmod(out, 0700) < 0)
	    die("Cannot chmod %s: %m", out);
	}

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
	  if (!strcmp(in, "proc"))
	    {
	      // If we are mounting procfs, add hidepid=2, so that only the processes
	      // of the same user are visible. This has to be done as a remount.
	      if (mount("none", root_in, out, MS_REMOUNT | mount_flags, "hidepid=2") < 0)
		die("Cannot re-mount proc with hidepid option: %m");
	    }
	}
      else
	{
	  mount_flags |= MS_BIND | MS_NOSUID;
	  if (!(r->flags & DIR_FLAG_NOREC))
	    mount_flags |= MS_REC;
	  msg("Binding %s on %s (flags %lx)\n", out, in, mount_flags);

	  /*
	   *  This is tricky. We cannot run mount() with root privileges, since
	   *  it could be used to bypass access control if the mounted path
	   *  contains elements inaccessible to the user running isolate.
	   *
	   *  We switch effective UID and GID back to the calling user (which clears
	   *  all capabilities, but keeps them in the permitted set) and then
	   *  enable CAP_SYS_ADMIN. So we have CAP_SYS_ADMIN (needed for mount),
	   *  but not CAP_DAC_OVERRIDE (which allows to bypass permission checks).
	   */

	  if (setresuid(orig_uid, orig_uid, 0) < 0 ||
	      setresgid(orig_gid, orig_gid, 0) < 0)
	    die("Cannot switch UID and GID: %m");

	  set_cap_sys_admin();

	  // Most mount flags need remount to work
	  if (mount(out, root_in, "none", mount_flags, "") < 0 ||
	      mount(out, root_in, "none", MS_REMOUNT | mount_flags, "") < 0)
	    die("Cannot mount %s on %s: %m", out, in);

	  if (setresuid(orig_uid, 0, orig_uid) < 0 ||
	      setresgid(orig_gid, 0, orig_gid) < 0)
	    die("Cannot switch UID and GID: %m");
	}
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

void
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
