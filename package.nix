{ lib
, stdenv
, asciidoc
, libcap
  # , systemdLibs
, installShellFiles
, pkg-config
, ...
}:

stdenv.mkDerivation {
  pname = "isolate";
  version = "2.0";

  src = ./.;

  nativeBuildInputs = [
    asciidoc
    installShellFiles
    pkg-config
  ];

  buildInputs = [
    libcap.dev
    # systemdLibs.dev
  ];

  buildFlags = [
    "--trace"
  ];

  installPhase = ''
    runHook preInstall

    install -Dm755 ./isolate $out/bin/isolate
    install -Dm755 ./isolate-cg-keeper $out/bin/isolate-cg-keeper
    installManPage isolate.1

    runHook postInstall
  '';

  meta = {
    description = "Sandbox for securely executing untrusted programs";
    mainProgram = "isolate";
    homepage = "https://github.com/ioi/isolate";
    license = lib.licenses.gpl2Plus;
    maintainers = with lib.maintainers; [ virchau13 ];
  };
}
