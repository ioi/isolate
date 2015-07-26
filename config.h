#ifndef __ISOLATE_CONFIG_H__
#define __ISOLATE_CONFIG_H__

/* A directory under which all sandboxes are created. */
#define CONFIG_ISOLATE_BOX_DIR "/tmp/box"

/* Range of UIDs and GIDs reserved for use by the sandboxes. */
#define CONFIG_ISOLATE_FIRST_UID 60000
#define CONFIG_ISOLATE_FIRST_GID 60000
#define CONFIG_ISOLATE_NUM_BOXES 100

/* Root of the cgroup hierarchy. */
#define CONFIG_ISOLATE_CGROUP_ROOT "/sys/fs/cgroup"

#endif /* __ISOLATE_CONFIG_H__ */
