/*
 *	A Trivial Helper Daemon for Keeping Control Groups in SystemD
 *
 *	(c) 2022 Martin Mares <mj@ucw.cz>
 */

#include "isolate.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int box_id;	// FIXME

void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  vfprintf(stderr, msg, args);
  fputc('\n', stderr);
  exit(1);
}

static void __attribute__((format(printf,2,3)))
write_cg_attr(const char *name, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  char namebuf[1024];
  snprintf(namebuf, sizeof(namebuf), "%s/%s", cf_cg_root, name);

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
setup_cg(void)
{
  struct stat st;
  if (stat(cf_cg_root, &st), 0)
    die("Control group root %s does not exist: %m", cf_cg_root);

  char subgroup[1024];
  snprintf(subgroup, sizeof(subgroup), "%s/daemon", cf_cg_root);
  if (mkdir(subgroup, 0777) < 0)
    die("Cannot create subgroup %s: %m", subgroup);

  write_cg_attr("daemon/cgroup.procs", "%d\n", (int) getpid());
  write_cg_attr("cgroup.subtree_control", "+cpuset +memory\n");	// FIXME
}

int
main(int argc UNUSED, char **argv UNUSED)
{
  cf_parse();
  setup_cg();
  for (;;)
    pause();
}
