/*
 *	Process Isolator
 *
 *	(c) 2012-2024 Martin Mares <mj@ucw.cz>
 *	(c) 2012-2014 Bernard Blackham <bernard@blackham.com.au>
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define NONRET __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define ARRAY_SIZE(a) (int)(sizeof(a)/sizeof(a[0]))

/* isolate.c */

void NONRET __attribute__((format(printf,1,2))) die(char *msg, ...);
void NONRET __attribute__((format(printf,1,2))) err(char *msg, ...);
void __attribute__((format(printf,1,2))) msg(char *msg, ...);

extern int pass_environ;
extern int verbose;
extern int block_quota;
extern int inode_quota;
extern int cg_enable;
extern int cg_memory_limit;

extern int box_id;
extern uid_t box_uid, orig_uid;
extern gid_t box_gid, orig_gid;

/* util.c */

void *xmalloc(size_t size);
char *xstrdup(char *str);
char * __attribute__((format(printf,1,2))) xsprintf(const char *fmt, ...);

void timespec_sub(const struct timespec *a, const struct timespec *b, struct timespec *result);

int dir_exists(char *path);
void rmtree(char *path);
void make_dir(char *path);
void make_dir_for(char *path);
void chowntree(char *path, uid_t uid, gid_t gid, bool keep_special_files);
void keep_fd(int fd);
void close_all_fds(void);

void meta_open(const char *name);
void meta_close(void);
void __attribute__((format(printf,1,2))) meta_printf(const char *fmt, ...);

/* rules.c */

int set_env_action(char *a0);
char **setup_environment(void);

void init_dir_rules(void);
int set_dir_action(char *arg);
void apply_dir_rules(int with_defaults);

void set_quota(void);

/* cg.c (without cg_enable, these functions do nothing) */

// Initialize CG machinery
void cg_init(void);

// Create a new CG for the box (during isolate --init)
void cg_create(void);

// Destroy the box CG (during isolate --cleanup)
void cg_remove(void);

// Prepare the box CG for use (during isolate --run)
void cg_setup(void);

// Move the current process to the box CG
void cg_enter(void);

// Obtain statistics on the box CG
int cg_get_run_time_ms(void);
void cg_stats(void);

/* config.c */

extern char *cf_box_root;
extern char *cf_lock_root;
extern char *cf_cg_root;
extern int cf_first_uid;
extern int cf_first_gid;
extern int cf_num_boxes;
extern int cf_restricted_init;

struct cf_per_box {
  struct cf_per_box *next;
  int box_id;
  char *cpus;
  char *mems;
};

void cf_parse(void);
struct cf_per_box *cf_per_box(int box_id);

static inline struct cf_per_box *
cf_current_box(void)
{
  return cf_per_box(box_id);
}
