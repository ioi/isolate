#!/bin/sh
#
# Identifies potential sources issues when using isolate.
#
#     (c) 2017 Bernard Blackham <bernard@blackham.com.au>
#

usage() {
    cat <<EOT >&2
Usage: $0 [-q|--quiet] [-e|--execute]

Use this script to identify sources of run-time variability and other issues on
Linux machines which may affect isolate. If --execute is not specified, the
recommended actions are written to stdout as an executable shell script,
otherwise, using --execute will attempt to make changes to make the system
behave more deterministically. The changes performed by --execute persist only
until a reboot. To persist across reboots, the standard output from this script
should be added to /etc/rc.local or some other script that is run on each boot.
Alternately, you could add the following line to /etc/rc.local to automatically
apply these changes on boot, but use this with caution as not all issues can
be resolved in this way.

    isolate-check-environment --quiet --execute

The exit status of this script will be 0 if all checks pass, or 1 if some
checks have failed.

Note that there are more strategies to reduce run-time variability further.
See the man page of isolate for details under REPRODUCIBILITY.
EOT
    exit 2
}

# Parse options.
args=$(getopt -o "ehq" --long "execute,help,quiet" -- "$@") || usage
eval set -- "$args"
quiet=
execute=
while : ; do
    case "$1" in
        -q|--quiet) quiet=1 ; shift ;;
        -e|--execute) execute=1 ; shift ;;
        -h|--help) usage ;;
        --) shift ; break ;;
        *) usage ;;
    esac
done
[ -n "$*" ] && usage

# Some helper boilerplate machinery.
exit_status=0
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
normal=$(tput sgr0)

# Return true (0) if we are being quiet.
quiet() {
    [ -n "$quiet" ]
}

# Print all arguments to stderr as warning.
warn() {
    quiet || echo WARNING: "$*" >&2
}

# Print first argument to stderr as warning, and second argument to stdout as
# the recommended remedial action, or execute if --execute is given.
action() {
    quiet || warn "$1"
    if [ -n "$execute" ] ; then
        quiet || echo "+ $2"
        sh -c "$2"
    else
        quiet || echo $2
    fi
}

print_start_check() {
    quiet && return
    print_check_status=1
    echo -n "Checking for $@ ... " >&2
}

print_fail() {
    exit_status=1
    quiet && return
    [ -n "$print_check_status" ] && echo "${red}FAIL${normal}" >&2
    print_check_status=
}

print_dubious() {
    exit_status=1
    quiet && return
    [ -n "$print_check_status" ] && echo "${yellow}CAUTION${normal}" >&2
    print_check_status=
}

print_skipped() {
    quiet && return
    [ -n "$print_check_status" ] && echo "SKIPPED (not detected)" >&2
    print_check_status=
}

print_finish() {
    quiet && return
    [ -n "$print_check_status" ] && echo "${green}PASS${normal}" >&2
    print_check_status=
}

# Check that cgroups are enabled.
cgroup_check() {
    local cgroup=$1
    print_start_check "cgroup support for $cgroup"
    if ! test -f "/sys/fs/cgroup/$cgroup/tasks" ; then
        print_dubious
        warn "the $cgroup is not present. isolate --cg cannot be used."
    fi
    print_finish
}
cgroup_check memory
cgroup_check cpuacct
cgroup_check cpuset

# Check that swap is either disabled or accounted for.
swap_check() {
    print_start_check "swap"
    # If swap is disabled, there is nothing to worry about.
    local swaps
    swaps=$(swapon --noheadings)
    if [ -n "$swaps" ] ; then
        # Swap is enabled.  We had better have the memsw support in the memory
        # cgroup.
        if ! test -f "/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes" ; then
            print_fail
            action \
                "swap is enabled, but swap accounting is not. isolate will not be able to enforce memory limits." \
                "swapoff -a"
        else
            print_dubious
            warn "swap is enabled, and although accounted for, may still give run-time variability under memory pressure."
        fi
    fi
    print_finish
}
swap_check

# Check that CPU frequency scaling is disabled.
cpufreq_check() {
    print_start_check "CPU frequency scaling"
    local anycpus policy
    anycpus=
    # Ensure cpufreq governor is set to performance on all CPUs
    for cpufreq_file in $(find /sys/devices/system/cpu/cpufreq/ -name scaling_governor) ; do
        policy=$(cat $cpufreq_file)
        if [ "$policy" != "performance" ] ; then
            print_fail
            action \
                "cpufreq governor set to '$policy', but 'performance' would be better" \
                "echo performance > $cpufreq_file"
        fi
        anycpus=1
    done
    [ -z "$anycpus" ] && print_skipped
    print_finish
}
cpufreq_check

# Check that address space layout randomisation is disabled.
aslr_check() {
    print_start_check "kernel address space randomisation"
    local val
    if val=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null) ; then
        if [ "$val" -ne 0 ] ; then
            print_fail
            action \
                "address space randomisation is enabled." \
                "echo 0 > /proc/sys/kernel/randomize_va_space"
        fi
    else
        print_skipped
    fi
    print_finish
}
aslr_check

# Check that transparent huge-pages are disabled, as this leads to
# non-determinism depending on whether the kernel can allocate 2 MiB pages or
# not.
thp_check() {
    print_start_check "transparent hugepage support"
    local val
    if val=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null) ; then
        case $val in
            *'[never]'*) ;;
            *) print_fail
               action \
                    "transparent hugepages are enabled." \
                    "echo never > /sys/kernel/mm/transparent_hugepage/enabled" ;;
        esac
    fi
    if val=$(cat /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null) ; then
        case $val in
            *'[never]'*) ;;
            *) print_fail
               action \
                    "transparent hugepage defrag is enabled." \
                    "echo never > /sys/kernel/mm/transparent_hugepage/defrag" ;;
        esac
    fi
    if val=$(cat /sys/kernel/mm/transparent_hugepage/khugepaged/defrag 2>/dev/null) ; then
        if [ "$val" -ne 0 ] ; then
            print_fail
            action \
                "khugepaged defrag is enabled." \
                "echo 0 > /sys/kernel/mm/transparent_hugepage/khugepaged/defrag"
        fi
    fi
    print_finish
}
thp_check


exit $exit_status
