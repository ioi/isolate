#!/bin/bash

set -e

QUIET=false
IGNORE_CHECK=false
ISOLATE_CHECK_EXECUTE=false
for arg in "$@"; do
    if [ "$arg" == "--help" ]; then
        echo "Usage: isolate [--quiet] [--ignore-check] [--execute-patches] [--help]"
        echo "  --quiet: Suppress outputs"
        echo "  --ignore-check: Do not fail if not properly setup"
        echo "  --execute-patches: Run isolate-check-environment --execute --quiet. Increases reproducibility."
        echo "  --help: Show this help message"
        break
    elif [ "$arg" == "--quiet" ]; then
        QUIET=true
    elif [ "$arg" == "--ignore-check" ]; then
        IGNORE_CHECK=true
    elif [ "$arg" == "--execute-patches" ]; then
        ISOLATE_CHECK_EXECUTE=true
    fi
done

print() {
    if [ $QUIET = false ]; then
        echo "$1"
    fi
}

if [ $ISOLATE_CHECK_EXECUTE = true ]; then
    print "Running isolate-check-environment --execute --quiet"
    isolate-check-environment --execute --quiet || true
fi

print "Rechecking environment"
if [ $IGNORE_CHECK = true ]; then
    print "Ignoring check"
    if [ $QUIET = true ]; then
        isolate-check-environment --quiet || true
    else
        isolate-check-environment || true
    fi
else
    print "Fail if not properly set up."
    if [ $QUIET = true ]; then
        isolate-check-environment --quiet
    else
        isolate-check-environment
    fi
    print "Environment is properly set up."
fi

# Run isolate daemon
print "Running isolate daemon"
exec isolate-cg-keeper
