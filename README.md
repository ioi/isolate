This is a fork of [isolate](https://github.com/ioi/isolate) with the additional configuration options:

* `n, --fnumber=<count>` — limits the number of open file descriptors (`ulimit -n`) to `<count>`. Defaults to 64.
* `--capability=<capability>` — propagates the capability (sets it as an ambient one) to the process run. E.g., `--capability=cap_ipc_lock`

isolate
=======

Isolate is a sandbox built to safely run untrusted executables,
offering them a limited-access environment and preventing them from
affecting the host system. It takes advantage of features specific to
the Linux kernel, like namespaces and control groups.

Isolate was developed by Martin Mareš (<mj@ucw.cz>) and Bernard Blackham
(<bernard@blackham.com.au>), who still maintain it. Several other people
contributed patches for features and bug fixes (see Git history for a list).
Thanks!

Originally, Isolate was a part of the [Moe Contest Environment](http://www.ucw.cz/moe/),
but it evolved to a separate project used by different
contest systems, most prominently [CMS](https://github.com/cms-dev/cms).
It now lives at [GitHub](https://github.com/ioi/isolate),
where you can submit bug reports and feature requests.

If you are interested in more details, please read Martin's
and Bernard's [paper](http://mj.ucw.cz/papers/isolate.pdf) presented
at the IOI Conference. Also, Isolate's [manual page](http://www.ucw.cz/moe/isolate.1.html)
is available online.

To compile Isolate, you need the headers for the libcap library
(usually available in a libcap-dev package).

You may need `a2x` (found in [AsciiDoc](http://www.methods.co.nz/asciidoc/a2x.1.html)) for building manual.
But if you only want the isolate binary, you can just run `make isolate`
