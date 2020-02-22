/*
 *	Process Isolator -- Capabilities
 *
 *	(c) 2020 Alexander Eliseyev <a.a.eliseyev@gmail.com>
 */
 
#include "isolate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>

struct configured_cap {
  cap_value_t cap_value;
  struct configured_cap *next;
};

static struct configured_cap* head_cap;

void add_capability(cap_value_t cap) {
	struct configured_cap* new_cap = malloc(sizeof(new_cap));

	new_cap->cap_value = cap;
	new_cap->next = head_cap;
	
	head_cap = new_cap;
}

void set_effective_capability(cap_value_t cap) {
  cap_t caps;
  if (!(caps = cap_get_proc()))
    die("Cannot get capabilities: %m");

  cap_value_t cap_list[] = { cap };
  if (cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_list, CAP_SET) < 0)
    die("Cannot modify capabilities");

  if (cap_set_proc(caps) < 0)
    die("Cannot set capabilities: %m");

  cap_free(caps);
}

void setup_capabilities(void) {
  for (struct configured_cap *c = head_cap; c; c=c->next) {
  	cap_value_t cap = c->cap_value;
  	set_effective_capability(cap);
  	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
	  die("Cannot raise ambient cap %d", cap);
	}
  }
}
