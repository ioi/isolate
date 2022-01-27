/*
 *	Process Isolator -- Utility Functions
 *
 *	(c) 2012-2022 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
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

static void
walktree_fd(int dir_fd, dev_t root_dev, void (*callback)(int dir_fd, const char *name, bool is_dir))
{
  DIR *dir = fdopendir(dir_fd);
  if (!dir)
    die("fdopendir failed: %m");

  struct dirent *de;
  while (de = readdir(dir))
    {
      if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
	continue;

      struct stat st;
      if (fstatat(dir_fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
	die("Cannot stat %s: %m", de->d_name);

      if (st.st_dev != root_dev)
	die("Unexpected mountpoint: %s", de->d_name);

      if (S_ISDIR(st.st_mode))
	{
	  int fd = openat(dir_fd, de->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	  if (fd < 0)
	    die("Cannot open directory %s: %m", de->d_name);
	  walktree_fd(fd, root_dev, callback);;
	  callback(dir_fd, de->d_name, 1);
	}
      else
	callback(dir_fd, de->d_name, 0);
    }

  closedir(dir);
}

static void
walktree(const char *path, void (*callback)(int dir_fd, const char *name, bool is_dir))
{
  int fd = open(path, O_RDONLY | O_DIRECTORY);
  if (fd < 0)
    die("Cannot open directory %s: %m", path);

  struct stat st;
  if (fstat(fd, &st) < 0)
    die("Cannot stat %s: %m", path);
  assert(S_ISDIR(st.st_mode));

  walktree_fd(fd, st.st_dev, callback);
  callback(AT_FDCWD, path, 1);
}

static void
rmtree_helper(int dir_fd, const char *name, bool is_dir)
{
  if (is_dir)
    {
      if (unlinkat(dir_fd, name, AT_REMOVEDIR) < 0)
	die("Cannot rmdir %s: %m", name);
    }
  else
    {
      if (unlinkat(dir_fd, name, 0) < 0)
	die("Cannot unlink %s: %m", name);
    }
}

void
rmtree(char *path)
{
  walktree(path, rmtree_helper);
}

static uid_t chown_uid;
static gid_t chown_gid;

static void
chowntree_helper(int dir_fd, const char *name, bool is_dir UNUSED)
{
  if (fchownat(dir_fd, name, chown_uid, chown_gid, AT_SYMLINK_NOFOLLOW) < 0)
    die("Cannot chown %s: %m", name);
}

void
chowntree(char *path, uid_t uid, gid_t gid)
{
  chown_uid = uid;
  chown_gid = gid;
  walktree(path, chowntree_helper);
}

static int fd_to_keep = -1;

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
      if (fd >= 0 && fd <= 2 || fd == dir_fd || fd == fd_to_keep)
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
  fd_to_keep = fileno(metafile);
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
