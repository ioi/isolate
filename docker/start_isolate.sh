#!/bin/bash

set -e

QUIET=true
SKIP_CHECK=true
ISOLATE_CHECK_EXECUTE=false
for arg in "$@"; do
    if [ "$arg" == "--help" ]; then
        echo "$(basename "$0")"
        echo "Usage: [--verbose] [--strict-check] [--execute-patches] [--help]"
        echo "  --verbose: Print every thing"
        echo "  --strict-check: Fail if patches not applied properly."
        echo "  --execute-patches: Run isolate-check-environment --execute --quiet. Increases reproducibility."
        echo "  --help: Show this help message"
        break
    elif [ "$arg" == "--verbose" ]; then
        QUIET=false
    elif [ "$arg" == "--strict-check" ]; then
        SKIP_CHECK=false
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
    isolate-check-environment --execute --quiet > /dev/null 2> /dev/null || true
fi

if [ $SKIP_CHECK = true ]; then
    print "Skipping check"
else
    print "Rechecking environment. Fail if not properly set up."
    if [ $QUIET = true ]; then
        isolate-check-environment --quiet > /dev/null 2> /dev/null
    else
        isolate-check-environment
    fi
    print "Environment is properly set up."
fi

# Run isolate daemon
print "Running isolate daemon"
exec isolate-cg-keeper
