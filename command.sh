#!/usr/bin/env bash

./oom_disposable.sh nix-shell --run 'time python3 parcheck.py quinn/Cargo.toml 16'