/*
 *	Process Isolator -- Control Groups
 *
 *	(c) 2012-2021 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include "isolate.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char cg_name[256];

#define CG_BUFSIZE 1024

static void
cg_makepath(char *buf, size_t len, const char *attr)
{
  int out;
  if (attr)
    out = snprintf(buf, len, "%s/%s/%s", cf_cg_root, cg_name, attr);
  else
    out = snprintf(buf, len, "%s/%s", cf_cg_root, cg_name);
  assert((size_t) out < len);
}

// FIXME: Unused yet
static int
cg_read(const char *attr, char *buf)
{
  int result = 0;
  int maybe = 0;
  if (attr[0] == '?')
    {
      attr++;
      maybe = 1;
    }

  char path[256];
  cg_makepath(path, sizeof(path), attr);

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
    msg("CG: Read %s = <%s>\n", attr, buf);

  result = 1;
fail_close:
  close(fd);
fail:
  return result;
}

static void __attribute__((format(printf,2,3)))
cg_write(const char *attr, const char *fmt, ...)
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
  cg_makepath(path, sizeof(path), attr);

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

static FILE *cg_fopen(const char *attr)
{
  char path[256];
  cg_makepath(path, sizeof(path), attr);

  FILE *f = fopen(path, "r");
  if (!f)
    die("Cannot open %s: %m", path);

  return f;
}

static void cg_fclose(FILE *f)
{
  if (ferror(f))
    die("Read error on cgroup attributes: %m");
  fclose(f);
}

static int cg_fread_kv(FILE *f, char *key, char *val)
{
  char line[CG_BUFSIZE];

  if (!fgets(line, sizeof(line), f))
    return 0;

  char *eol = strchr(line, '\n');
  if (!eol)
    die("Non-terminated or too long line in cgroup key-value file");
  *eol = 0;

  char *space = strchr(line, ' ');
  if (!space)
    die("Missing space in cgroup key-value file");
  *space = 0;

  strcpy(key, line);
  strcpy(val, space + 1);
  return 1;
}

void
cg_init(void)
{
  if (!cg_enable)
    return;

  if (!dir_exists(cf_cg_root))
    die("Master control group %s does not exist", cf_cg_root);

  snprintf(cg_name, sizeof(cg_name), "box-%d", box_id);

  msg("Using control group %s under parent %s\n", cg_name, cf_cg_root);
}

void
cg_prepare(void)
{
  if (!cg_enable)
    return;

  struct stat st;
  char path[256];

  cg_makepath(path, sizeof(path), NULL);
  if (stat(path, &st) >= 0 || errno != ENOENT)
    {
      msg("Control group %s already exists, trying to empty it.\n", path);
      if (rmdir(path) < 0)
	die("Failed to reset control group %s: %m", path);
    }

  if (mkdir(path, 0777))
    die("Failed to create control group %s: %m", path);
}

void
cg_enter(void)
{
  if (!cg_enable)
    return;

  msg("Entering control group %s\n", cg_name);

  cg_write("cgroup.procs", "%d\n", (int) getpid());

  if (cg_memory_limit)
    {
      cg_write("memory.max", "%lld\n", (long long) cg_memory_limit << 10);
      cg_write("memory.swap.max", "0\n");
    }

  struct cf_per_box *cf = cf_current_box();
  if (cf->cpus)
    cg_write("cpuset.cpus", "%s", cf->cpus);
  if (cf->mems)
    cg_write("cpuset.mems", "%s", cf->mems);
}

int
cg_get_run_time_ms(void)
{
  if (!cg_enable)
    return 0;

  FILE *f = cg_fopen("cpu.stat");
  unsigned long long usec = 0;
  int found_usage = 0;

  char key[CG_BUFSIZE], val[CG_BUFSIZE];
  while (cg_fread_kv(f, key, val))
    {
      if (!strcmp(key, "usage_usec"))
	{
	  usec = atoll(val);
	  found_usage = 1;
	}
    }

  cg_fclose(f);
  if (!found_usage)
    die("Missing usage_usec in cpu.stat");

  return usec / 1000;
}

void
cg_stats(void)
{
  if (!cg_enable)
    return;

  char key[CG_BUFSIZE], val[CG_BUFSIZE];

#if 0	// FIXME: I see no way how to ask for maximum memory usage
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
#endif

  // OOM kill detection
  FILE *f = cg_fopen("memory.events");
  while (cg_fread_kv(f, key, val))
    {
      if (!strcmp(key, "oom_kill") && atoll(val))
	{
	  meta_printf("cg-oom-killed:1\n");
	  break;
	}
    }
  cg_fclose(f);
}

void
cg_remove(void)
{
  if (!cg_enable)
    return;

  cg_write("?cgroup.kill", "1\n");

  char path[256];
  cg_makepath(path, sizeof(path), NULL);
  if (rmdir(path) < 0)
    die("Cannot remove control group %s: %m", path);
}
