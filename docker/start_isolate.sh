#!/bin/sh

set -e

QUIET=true
ISOLATE_CHECK_EXECUTE=false
STRICT=false
for arg in "$@"; do
    case $arg in
        --verbose)
            QUIET=false
            ;;
        --execute-patches)
            ISOLATE_CHECK_EXECUTE=true
            ;;
        --strict)
            STRICT=true
            ;;
        --help)
            echo "$(basename "$0")"
            echo "Usage: [--verbose] [--execute-patches] [--help]"
            echo "  --verbose: Print every thing"
            echo "  --execute-patches: Run isolate-check-environment --execute --quiet. Increases reproducibility."
            echo "  --strict: Fail if isolate-check-environment fails."
            echo "  --help: Show this help message"
            exit 0
            ;;
    esac
done

print() {
    if [ $QUIET = false ]; then
        echo "$1"
    fi
}

# Will return 0 if rw is attribute of /sys/fs/cgroup
if ! findmnt -O rw /sys/fs/cgroup; then
    print "/sys/fs/cgroup read-only. Remounting as read-write."
    mount -o remount,rw /sys/fs/cgroup/
fi

# Run isolate daemon
print "Running isolate daemon"
isolate-cg-keeper --move-cg-neighbors & DAEMON_PID=$!

if [ $ISOLATE_CHECK_EXECUTE = true ]; then
    print "Running isolate-check-environment --execute --quiet"
    isolate-check-environment --execute --quiet > /dev/null 2> /dev/null || true
fi

if [ $STRICT = true ]; then
    print "Running isolate-check-environment"
    if [ $QUIET = true ]; then
        isolate-check-environment --quiet > /dev/null 2> /dev/null
    else
        isolate-check-environment
    fi
else
    print "Skipping isolate-check-environment"
fi

wait $DAEMON_PID
