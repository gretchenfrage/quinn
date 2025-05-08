{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.python3
    pkgs.python3Packages.virtualenv
    pkgs.git
    pkgs.cargo
  ];

  shellHook = ''
    if [ ! -d .venv ]; then
      echo "Creating virtualenv in .venv"
      python3 -m venv .venv
    fi
    source .venv/bin/activate

    if ! pip show psutil >/dev/null 2>&1; then
      echo "Installing psutil"
      pip install psutil
    fi

    echo "Activated virtualenv and ready to run"
  '';
}
