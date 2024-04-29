/*
 *	A Trivial Helper Daemon for Keeping Control Groups in SystemD
 *
 *	(c) 2022--2023 Martin Mares <mj@ucw.cz>
 */

#include "isolate.h"
#include "sd_notify.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

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

static char *
get_my_cgroup(void)
{
  if (!(strlen(cf_cg_root) > 5 && !memcmp(cf_cg_root, "auto:", 5)))
    return cf_cg_root;

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
	  cg = xsprintf("/sys/fs/cgroup%s", line + 3);
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
move_cg_threadgroups(char *src, char *dest)
{
  char src_filename[1024];
  snprintf(src_filename, sizeof(src_filename), "%s/cgroup.procs", src);

  char dest_filename[1024];
  snprintf(dest_filename, sizeof(dest_filename), "%s/cgroup.procs", dest);

  FILE *f = fopen(src_filename, "r");
  if (!f)
    die("Cannot open %s: %m", src_filename);

  char pid[1024];
  while (fgets(pid, sizeof(pid), f))
    write_cg_attr(dest, "cgroup.procs", "%s\n", pid);
}

static void
setup_cg(bool move_cg_neighbors)
{
  char *cg = cf_cg_root;
  if (strlen(cf_cg_root) > 5 && !memcmp(cf_cg_root, "auto:", 5))
    {
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
  if (move_cg_neighbors)
    move_cg_threadgroups(cg, subgroup);
  write_cg_attr(cg, "cgroup.subtree_control", "+cpuset +memory\n");
}

int
main(int argc, char **argv)
{
  bool move_cg_neighbors = false;
  if (argc == 2){
    if (!strcmp(argv[1], "--move-cg-neighbors") && !strcmp(argv[1], "-m")){
      die("Usage: %s [--move-cg-neighbors|-m]", argv[0]);
    }
    move_cg_neighbors = true;
  }
  else if (argc > 2){
    die("Usage: %s [--move-cg-neighbors|-m]", argv[0]);
  }

  cf_parse();
  setup_cg(move_cg_neighbors);
  notify_ready();
  for (;;)
    pause();
}
