#!/bin/bash

set -e

QUIET=true
ISOLATE_CHECK_EXECUTE=false
for arg in "$@"; do
    if [ "$arg" == "--help" ]; then
        echo "$(basename "$0")"
        echo "Usage: [--verbose] [--execute-patches] [--help]"
        echo "  --verbose: Print every thing"
        echo "  --execute-patches: Run isolate-check-environment --execute --quiet. Increases reproducibility."
        echo "  --help: Show this help message"
        break
    elif [ "$arg" == "--verbose" ]; then
        QUIET=false
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
    if [ $QUIET = false ]; then
        print "Running isolate-check-environment --execute"
        isolate-check-environment --execute || true
    else
        print "Running isolate-check-environment --execute --quiet"
        isolate-check-environment --execute --quiet > /dev/null 2> /dev/null || true
    fi
fi

# Run isolate daemon
print "Running isolate daemon"
isolate-cg-keeper --move-cg-neighbors
