/*
 *	Process Isolator -- Utility Functions
 *
 *	(c) 2012-2023 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void *
xmalloc(size_t size)
{
  void *p = malloc(size);
  if (!p)
    die("Out of memory");
  return p;
}

char *
xstrdup(char *str)
{
  char *p = strdup(str);
  if (!p)
    die("Out of memory");
  return p;
}

char *xsprintf(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  char *out;
  int res = vasprintf(&out, fmt, args);
  if (res < 0)
    die("Out of memory");

  va_end(args);
  return out;
}

void
timespec_sub(const struct timespec *a, const struct timespec *b, struct timespec *result)
{
  result->tv_sec  = a->tv_sec - b->tv_sec;
  result->tv_nsec = a->tv_nsec - b->tv_nsec;

  if (result->tv_nsec < 0)
  {
    result->tv_sec  -= 1;
    result->tv_nsec += 1000000000L;
  }
}

int
dir_exists(char *path)
{
  struct stat st;
  return (stat(path, &st) >= 0 && S_ISDIR(st.st_mode));
}

void
make_dir(char *path)
{
  char *sep = (path[0] == '/' ? path+1 : path);

  for (;;)
    {
      sep = strchr(sep, '/');
      if (sep)
	*sep = 0;

      if (mkdir(path, 0777) < 0 && errno != EEXIST)
	die("Cannot create directory %s: %m", path);

      if (!sep)
	break;
      *sep++ = '/';
    }

 // mkdir() above may have returned EEXIST even if the path was not
 // a directory. Ensure that it is.
  struct stat st;
  if (stat(path, &st) < 0)
    die("Cannot stat %s: %m", path);
  if (!S_ISDIR(st.st_mode))
    die("Cannot create %s: already exists, but not a directory", path);
}

void make_dir_for(char *path)
{
  char *copy = xstrdup(path);
  char *last_slash = strrchr(copy, '/');
  if (last_slash)
    {
      *last_slash = 0;
      make_dir(copy);
    }
  free(copy);
}

/*
 *  Once upon a time, we used nftw() for traversing directory trees.
 *  It was simple, but unfortunately prone to symlink swapping attacks.
 *  Using FTW_CHDIR would prevent the attacks, but it interacts badly with
 *  FTW_DEPTH which we need when removing directory trees. See bug report at
 *  https://sourceware.org/bugzilla/show_bug.cgi?id=28831.
 *
 *  We therefore switched to our implementation based on using openat(),
 *  fstatat() and similar functions.
 */

struct walk_context {
    // Current item
    int dir_fd;
    const char *name;
    bool is_dir;
    struct stat st;

    // Common for the whole walk
    dev_t root_dev;
    void (*callback)(struct walk_context *ctx);

    // Used by our callbacks
    uid_t chown_uid;
    gid_t chown_gid;
    bool keep_special_files;
};

static void
walktree_ctx(struct walk_context *ctx)
{
  DIR *dir = fdopendir(ctx->dir_fd);
  if (!dir)
    die("fdopendir failed: %m");

  struct dirent *de;
  while (de = readdir(dir))
    {
      ctx->name = de->d_name;

      if (!strcmp(ctx->name, ".") || !strcmp(ctx->name, ".."))
	continue;

      if (fstatat(ctx->dir_fd, ctx->name, &ctx->st, AT_SYMLINK_NOFOLLOW) < 0)
	die("Cannot stat %s: %m", ctx->name);

      if (ctx->st.st_dev != ctx->root_dev)
	die("Unexpected mountpoint: %s", ctx->name);

      if (S_ISDIR(ctx->st.st_mode))
	{
	  struct walk_context subdir = *ctx;
	  subdir.dir_fd = openat(ctx->dir_fd, ctx->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	  if (subdir.dir_fd < 0)
	    die("Cannot open directory %s: %m", ctx->name);
	  walktree_ctx(&subdir);
	  ctx->is_dir = true;
	  ctx->callback(ctx);
	}
      else
	{
	  ctx->is_dir = false;
	  ctx->callback(ctx);
	}
    }

  closedir(dir);
}

static void
walktree(struct walk_context *ctx, const char *path, void (*callback)(struct walk_context *ctx))
{
  ctx->callback = callback;
  ctx->dir_fd = AT_FDCWD;
  ctx->name = path;

  struct walk_context top = *ctx;
  top.dir_fd = open(path, O_RDONLY | O_DIRECTORY);
  if (top.dir_fd < 0)
    die("Cannot open directory %s: %m", path);

  if (fstat(top.dir_fd, &ctx->st) < 0)
    die("Cannot stat %s: %m", path);
  assert(S_ISDIR(ctx->st.st_mode));
  top.root_dev = ctx->st.st_dev;

  walktree_ctx(&top);

  ctx->is_dir = true;
  ctx->callback(ctx);
}

static void
rmtree_helper(struct walk_context *ctx)
{
  if (ctx->is_dir)
    {
      if (unlinkat(ctx->dir_fd, ctx->name, AT_REMOVEDIR) < 0)
	die("Cannot rmdir %s: %m", ctx->name);
    }
  else
    {
      if (unlinkat(ctx->dir_fd, ctx->name, 0) < 0)
	die("Cannot unlink %s: %m", ctx->name);
    }
}

void
rmtree(char *path)
{
  struct walk_context ctx = { };
  walktree(&ctx, path, rmtree_helper);
}

static void
chowntree_helper(struct walk_context *ctx)
{
  if (S_ISREG(ctx->st.st_mode) || S_ISDIR(ctx->st.st_mode) || ctx->keep_special_files)
    {
      if (fchownat(ctx->dir_fd, ctx->name, ctx->chown_uid, ctx->chown_gid, AT_SYMLINK_NOFOLLOW) < 0)
	die("Cannot chown %s: %m", ctx->name);
    }
  else
    {
      if (unlinkat(ctx->dir_fd, ctx->name, 0) < 0)
	die("Cannot unlink special file %s: %m", ctx->name);
    }
}

void
chowntree(char *path, uid_t uid, gid_t gid, bool keep_special_files)
{
  struct walk_context ctx = {
      .chown_uid = uid,
      .chown_gid = gid,
      .keep_special_files = keep_special_files,
  };
  walktree(&ctx, path, chowntree_helper);
}

static int fds_to_keep[4];
static int num_kept_fds;

void
keep_fd(int fd)
{
  assert(num_kept_fds < ARRAY_SIZE(fds_to_keep));
  fds_to_keep[num_kept_fds++] = fd;
}

static bool
fd_is_kept(int fd)
{
  for (int i=0; i < num_kept_fds; i++)
    if (fds_to_keep[i] == fd)
      return true;
  return false;
}

void
close_all_fds(void)
{
  /* Close all file descriptors except 0, 1, 2 */

  DIR *dir = opendir("/proc/self/fd");
  if (!dir)
    die("Cannot open /proc/self/fd: %m");
  int dir_fd = dirfd(dir);

  struct dirent *e;
  while (e = readdir(dir))
    {
      char *end;
      long int fd = strtol(e->d_name, &end, 10);
      if (*end)
	continue;
      if (fd >= 0 && fd <= 2 || fd == dir_fd || fd_is_kept(fd))
	continue;
      close(fd);
    }

  closedir(dir);
}

/*** Meta-files ***/

static FILE *metafile;

void
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
  keep_fd(fileno(metafile));
}

void
meta_close(void)
{
  if (metafile && metafile != stdout)
    fclose(metafile);
}

void
meta_printf(const char *fmt, ...)
{
  if (!metafile)
    return;

  va_list args;
  va_start(args, fmt);
  vfprintf(metafile, fmt, args);
  va_end(args);
}
