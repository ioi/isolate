#include "isolate.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <systemd/sd-bus.h>

void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  char buf[1024];
  vsnprintf(buf, sizeof(buf), msg, args);

  fputs(buf, stderr);
  fputc('\n', stderr);
  exit(1);
}

#define CHECK_ERR do { if (err < 0) die("%d: error %d", __LINE__, err); } while (0)

static int match_job_removed(sd_bus_message *msg, void *userdata UNUSED, sd_bus_error *error UNUSED)
{
  int err;

  uint32_t id;
  const char *path, *unit, *result;
  err = sd_bus_message_read(msg, "uoss", &id, &path, &unit, &result);
  CHECK_ERR;

  printf("Job removed: path=<%s> unit=<%s> result=<%s>\n", path, unit, result);

  return 0;
}

static void prop_str(sd_bus_message *msg, const char *key, const char *val)
{
  int err = sd_bus_message_append(msg, "(sv)", key, "s", val);
  CHECK_ERR;
}

static void prop_bool(sd_bus_message *msg, const char *key, int val)
{
  int err = sd_bus_message_append(msg, "(sv)", key, "b", (int32_t) val);
  CHECK_ERR;
}

int main(void)
{
  sd_bus *bus;
  int err;

  err = sd_bus_default_system(&bus);
  if (err < 0)
    die("sd_bus_default_system: error %d", err);

  char name[256];
  snprintf(name, sizeof(name), "isolate-%d.scope", (int) getpid());

  err = sd_bus_match_signal(
    bus,
    NULL,	// FIXME: Remove match later?
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
    "JobRemoved",
    match_job_removed,
    NULL);
  CHECK_ERR;

  sd_bus_message *msg = NULL, *reply = NULL;
  err = sd_bus_message_new_method_call(
    bus,
    &msg,
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
    "StartTransientUnit");
  CHECK_ERR;

  err = sd_bus_message_append(msg, "ss", name, "fail");
  CHECK_ERR;

  err = sd_bus_message_open_container(msg, 'a', "(sv)");
  CHECK_ERR;

  prop_str(msg, "Description", "Test Scope");
  prop_str(msg, "Slice", "isolate.slice");
  prop_bool(msg, "Delegate", 1);

  err = sd_bus_message_append(msg, "(sv)", "PIDs", "au", 1, (uint32_t) getpid());
  CHECK_ERR;

  err = sd_bus_message_close_container(msg);
  CHECK_ERR;

  err = sd_bus_message_append(msg, "a(sa(sv))", 0);
  CHECK_ERR;

  sd_bus_error bus_err = SD_BUS_ERROR_NULL;
  err = sd_bus_call(bus, msg, 0, &bus_err, &reply);
  CHECK_ERR;

  const char *object = NULL;
  err = sd_bus_message_read(reply, "o", &object);
  CHECK_ERR;

  printf("Object: <%s>\n", object);

  for (;;)
    {
      err = sd_bus_process(bus, NULL);
      CHECK_ERR;

      if (!err)
	{
	  err = sd_bus_wait(bus, UINT64_MAX);
	  CHECK_ERR;
	}
    }

  return 0;
}
