/*
 *	A Trivial Helper Daemon for Keeping Control Groups in SystemD
 *
 *	(c) 2022--2024 Martin Mares <mj@ucw.cz>
 */

#include "isolate.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <systemd/sd-daemon.h>

#define CGROUP_FS "/sys/fs/cgroup"

void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  vfprintf(stderr, msg, args);
  fputc('\n', stderr);
  exit(1);
}

static void __attribute__((format(printf,3,4)))
write_cg_attr(const char *cg_root, const char *name, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  char namebuf[1024];
  snprintf(namebuf, sizeof(namebuf), "%s/%s", cg_root, name);

  char valbuf[1024];
  vsnprintf(valbuf, sizeof(valbuf), fmt, args);
  int len = strlen(valbuf);

  int fd = open(namebuf, O_WRONLY);
  if (fd < 0)
    die("Cannot open %s: %m", namebuf);

  if (write(fd, valbuf, len) != len)
    die("Cannot write to %s: %m", namebuf);

  close(fd);
  va_end(args);
}

static void
check_cgroup_fs(void)
{
  struct stat st;

  if (stat(CGROUP_FS, &st) < 0)
    die("Cannot find %s: %m", CGROUP_FS);

  if (stat(CGROUP_FS "/unified", &st) >= 0)
    die("Combined cgroup v1+v2 mode is not supported");

  if (stat(CGROUP_FS "/cgroup.subtree_control", &st) < 0)
    die("Cgroup v2 not found");
}

static char *
get_my_cgroup(void)
{
  FILE *f = fopen("/proc/self/cgroup", "r");
  if (!f)
    die("Cannot open /proc/self/cgroup: %m");

  char *line = NULL;
  size_t buflen = 0;
  ssize_t len;
  char *cg = NULL;

  while ((len = getline(&line, &buflen, f)) >= 0)
    {
      if (len > 0 && line[len-1] == '\n')
	line[--len] = 0;
      if (line[0] == '0' && line[1] == ':' && line[2] == ':')
	{
	  cg = xsprintf(CGROUP_FS "%s", line + 3);
	  break;
	}
    }

  if (!cg)
    die("Cannot find my own cgroup");

  free(line);
  fclose(f);
  return cg;
}

static void
write_auto_cgroup(char *file, char *cg)
{
  make_dir_for(file);

  FILE *f = fopen(file, "w");
  if (!f)
    die("Cannot create %s: %m", file);
  fprintf(f, "%s\n", cg);
  fclose(f);
}

static void
setup_cg(void)
{
  char *cg = cf_cg_root;
  if (strlen(cf_cg_root) > 5 && !memcmp(cf_cg_root, "auto:", 5))
    {
      check_cgroup_fs();
      cg = get_my_cgroup();
      write_auto_cgroup(cf_cg_root + 5, cg);
    }

  struct stat st;
  if (stat(cg, &st), 0)
    die("Control group root %s does not exist: %m", cg);

  char subgroup[1024];
  snprintf(subgroup, sizeof(subgroup), "%s/daemon", cg);
  if (mkdir(subgroup, 0777) < 0)
    die("Cannot create subgroup %s: %m", subgroup);

  write_cg_attr(cg, "daemon/cgroup.procs", "%d\n", (int) getpid());
  write_cg_attr(cg, "cgroup.subtree_control", "+cpuset +memory\n");
}

int
main(int argc UNUSED, char **argv UNUSED)
{
  cf_parse();
  setup_cg();
  sd_notify(0, "READY=1");
  for (;;)
    pause();
}
