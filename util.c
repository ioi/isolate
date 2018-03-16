/*
 *	Process Isolator -- Utility Functions
 *
 *	(c) 2012-2017 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <dirent.h>
#include <errno.h>
#include <ftw.h>
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


static int
rmtree_helper(const char *fpath, const struct stat *sb, int typeflag UNUSED, struct FTW *ftwbuf UNUSED)
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
  return 0;
}

void
rmtree(char *path)
{
  nftw(path, rmtree_helper, 32, FTW_MOUNT | FTW_PHYS | FTW_DEPTH);
}

static uid_t chown_uid;
static gid_t chown_gid;

static int
chowntree_helper(const char *fpath, const struct stat *sb UNUSED, int typeflag UNUSED, struct FTW *ftwbuf UNUSED)
{
  if (lchown(fpath, chown_uid, chown_gid) < 0)
    die("Cannot chown %s: %m", fpath);
  else
    return 0;
}

void
chowntree(char *path, uid_t uid, gid_t gid)
{
  chown_uid = uid;
  chown_gid = gid;
  nftw(path, chowntree_helper, 32, FTW_MOUNT | FTW_PHYS);
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
