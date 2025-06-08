isolate
=======

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
Also, Isolate's [manual page](http://www.ucw.cz/isolate/isolate.1.html)
is available online.

## Installing Isolate

To compile Isolate, you need:

  - pkg-config

  - headers for the libcap library (usually available in a libcap-dev package)

  - headers for the libsystemd library (libsystemd-dev package) for compilation
    of isolate-cg-keeper

You may need `a2x` (found in [AsciiDoc](https://asciidoc-py.github.io/a2x.1.html)) for building manual.
But if you only want the isolate binary, you can just run `make isolate`

Recommended system setup is described in sections INSTALLATION and REPRODUCIBILITY
of the manual page.

## Debian packages

Isolate is also available as packages for stable Debian Linux and last two LTS
releases of Ubuntu, all on the amd64 architecture. To use them, add the following
to your `/etc/apt/sources.list`:

    deb [arch=amd64 signed-by=/etc/apt/keyrings/isolate.asc] http://www.ucw.cz/isolate/debian/ bookworm-isolate main

You also need to install the repository's public key:

    curl https://www.ucw.cz/isolate/debian/signing-key.asc >/etc/apt/keyrings/isolate.asc

Then invoke:

    apt update && apt install isolate

There are experimental packages for the arm64 architecture, too.
