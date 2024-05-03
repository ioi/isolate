# isolate

Isolate is a sandbox built to safely run untrusted executables, like
programs submitted by competitors in a programming contest. Isolate
gives them a limited-access environment, preventing them from affecting
the host system. It takes advantage of features specific to the Linux
kernel, like namespaces and control groups.

Isolate was developed by Martin Mareš (<mj@ucw.cz>) and Bernard Blackham
(<bernard@blackham.com.au>) and still maintained by the former author.
Several other people contributed patches for features and bug fixes
(see Git history for a list). Thanks!

Originally, Isolate was a part of the [Moe Contest Environment](http://www.ucw.cz/moe/),
but it evolved to a separate project used by different
contest systems, most prominently [CMS](https://github.com/cms-dev/cms).
It now lives at [GitHub](https://github.com/ioi/isolate),
where you can submit bug reports and feature requests.

If you are interested in more details, please read Martin's and Bernard's
papers on [Isolate's design](https://mj.ucw.cz/papers/isolate.pdf) and
[grading system security](https://mj.ucw.cz/papers/secgrad.pdf) published
in the Olympiads in Informatics journal.
Also, Isolate's [manual page](http://www.ucw.cz/moe/isolate.1.html)
is available online.

## Quick start with Docker

The fastest way to start is grabbing the pre-built docker image at `ghcr.io/minhnhatnoe/isolate:latest`, which can be used as a standalone image or a base image.

### Standalone

Run the container with the `--privileged` flag to start the daemon. Make sure you mount appropriate directories to the default mount points at `/bin`, `/lib` and `/usr` (and probably `/var/local/lib/isolate/` to put executable in the sandbox).

Use `docker exec` to trigger `isolate` runs (refer to the man page for additional details). A good starting point would be `isolate --cg --init && isolate --cg --run -- <program> && isolate --cg --cleanup`.

### Base image

In your resulting image, install libcap (usually available as `libcap` and/or `libcap-dev`) and run the daemon with either `isolate-cg-keeper --move-cg-neighbors` or `start_isolate` (note that both will be blocking).

### Permissions

Privileges could be granted to the container in a more fine-grained manner. Practically, the container needs only `CAP_SYS_ADMIN` (for remounting cgroups as read-write) and `CAP_NET_ADMIN` (for creating sandbox network interfaces). Instead of using `--privileged`, you could grant only these capabilities with `--cap-add CAP_SYS_ADMIN --cap-add CAP_NET_ADMIN`.

Note that `isolate-check-environment --execute` requires access to multiple other directories, so it may only be run with `--privileged`.

## Building from source

### Installation

To compile Isolate, you need:

- pkg-config
- headers for the libcap library (usually available in a libcap-dev package)

You may need `a2x` (found in [AsciiDoc](https://asciidoc-py.github.io/a2x.1.html)) for building manual.
But if you only want the isolate binary, you can just run `make isolate`

Recommended system setup is described in sections INSTALLATION and REPRODUCIBILITY
of the manual page. To install the systemd unit, run `make install-systemd-units`.

### Usage

If your system is using systemd, run the installed unit (usually with `systemctl enable isolate --now`) and you're ready to use `isolate`.

## Anatomy of isolate

- `isolate-cg-keeper`: Establish the Control Group subtree for running processes and future sandboxes. Should be started before running any `isolate` and `isolate-check-environment` commands. If `isolate-cg-keeper` is not the sole process at its designated Control Group, execute with `--move-cg-neighbors` to avoid violating [Control Group v2's No Internal Process Constraint](https://docs.kernel.org/admin-guide/cgroup-v2.html#no-internal-process-constraint).
- `isolate-check-environment`: Check current environment for sources of run-time variability and other issues. Should be run after starting `isolate-cg-keeper`. To apply recommended fixes, run with `--execute`.
- `isolate`: The sandbox trigger. Refer to the man page for guidance.
