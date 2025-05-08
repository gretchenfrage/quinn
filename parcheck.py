#!/usr/bin/env python3

import argparse
import itertools
import json
import math
import os
import queue
import random
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

stop_event = threading.Event()
progress_queue = queue.Queue()
retry_queue = queue.Queue()
failure_count = 0
failure_lock = threading.Lock()
active_subprocesses = set()
active_units = set()
subprocess_lock = threading.Lock()

repo_root = Path(os.getcwd()).resolve()

def log(msg):
    print(msg, flush=True)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest_path", help="Path to Cargo.toml")
    parser.add_argument("thread_count", type=int, help="Number of threads to use")
    return parser.parse_args()

def create_temp_dirs(thread_count):
    base_temp = Path(tempfile.gettempdir()) / f"cargo_check_{uuid.uuid4()}"
    base_temp.mkdir()
    subdirs = []
    for i in range(thread_count):
        subdir = base_temp / f"thread_{i}"
        subdir.mkdir()
        subdirs.append(subdir)
    return base_temp, subdirs

def clone_repo_into(dest, source_git_dir):
    subprocess.run(["git", "clone", "--local", source_git_dir, str(dest)], check=True)

def get_features(manifest_path):
    result = subprocess.run(
        ["cargo", "metadata", "--manifest-path", manifest_path, "--no-deps", "--format-version=1"],
        capture_output=True,
        text=True,
        check=True,
    )
    metadata = json.loads(result.stdout)
    return list(metadata["packages"][0]["features"].keys())

def compute_powerset(features):
    powerset = list(itertools.chain.from_iterable(
        itertools.combinations(features, r) for r in range(len(features) + 1)
    ))
    random.shuffle(powerset)
    return powerset

def run_check(combo, thread_dir, manifest_rel_path, failure_log_path):
    feature_str = ",".join(combo)

    unit_name = f"oomjob-{os.getpid()}-{uuid.uuid4().hex}"
    with subprocess_lock:
        active_units.add(unit_name)

    args = [
        "systemd-run", "--user",
        f"--unit={unit_name}",
        "--slice=oomdisposable.slice",
        f"--working-directory={thread_dir}",
        "-p", "OOMPolicy=kill",
        "-p", "CPUWeight=1",
        "-p", "IOWeight=1",
        "-p", "ManagedOOMMemoryPressure=kill",
        "--wait", "--collect", "--quiet",
        "cargo", "check", "-j", "1", "--manifest-path", manifest_rel_path
    ]
    if combo:
        args += ["--no-default-features", "--features", feature_str]

    with subprocess_lock:
        if stop_event.is_set():
            return
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        active_subprocesses.add(proc)

    try:
        stdout, stderr = '', ''
        while True:
            try:
                stdout, stderr = proc.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                if stop_event.is_set():
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    return
        retcode = proc.returncode
    finally:
        with subprocess_lock:
            active_subprocesses.discard(proc)
            active_units.discard(unit_name)

        # Cleanup the transient unit in case it lingers
        subprocess.run(["systemctl", "--user", "stop", unit_name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if retcode == 137:
        retry_queue.put(combo)
    elif retcode != 0:
        with failure_lock:
            global failure_count
            failure_count += 1
        with open(failure_log_path, "a") as f:
            f.write(f"FAILED: {feature_str}\n")
            f.write(stdout)
            f.write(stderr)
            f.write("\n" + "-" * 80 + "\n")

    progress_queue.put(1)

def worker_thread(index, thread_dir, manifest_rel_path, failure_log_path):
    try:
        while not stop_event.is_set():
            try:
                combo = retry_queue.get_nowait()
            except queue.Empty:
                time.sleep(0.1)
                continue
            run_check(combo, thread_dir, manifest_rel_path, failure_log_path)
    except Exception as e:
        log(f"Worker {index} crashed: {e}")

def format_eta(seconds):
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes or hours:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts) + " remaining"

def progress_watcher(total):
    completed = 0
    bar_len = 40
    start_time = time.time()

    while completed < total:
        if stop_event.is_set() and progress_queue.empty():
            break
        try:
            progress_queue.get(timeout=0.2)
            completed += 1
            elapsed = time.time() - start_time
            rate = elapsed / completed if completed else 1
            remaining = total - completed
            eta = format_eta(remaining * rate)

            filled = int(bar_len * completed / total)
            bar = "#" * filled + "-" * (bar_len - filled)
            with failure_lock:
                fail_count = failure_count
            print(f"\rProgress: [{bar}] {completed}/{total} ({fail_count} failed, {eta}) | {threading.active_count() - 2} workers active", end="", flush=True)
        except queue.Empty:
            continue
    print()

def stop_all_units():
    with subprocess_lock:
        for unit in list(active_units):
            subprocess.run(["systemctl", "--user", "stop", unit],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        active_units.clear()

def main():
    args = parse_args()
    manifest_path = Path(args.manifest_path).resolve()
    manifest_rel = manifest_path.relative_to(repo_root)

    base_temp, thread_dirs = create_temp_dirs(args.thread_count)
    failure_log_path = base_temp / "failures.txt"
    log(f"Using temp root: {base_temp}")
    log(f"Failures logged to: {failure_log_path}")

    def on_signal(sig, frame):
        log("\nInterrupt received. Cleaning up.")
        stop_event.set()

        stop_all_units()

        with subprocess_lock:
            for proc in list(active_subprocesses):
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

        while not retry_queue.empty():
            try:
                retry_queue.get_nowait()
            except queue.Empty:
                break

    signal.signal(signal.SIGINT, on_signal)

    try:
        for d in thread_dirs:
            clone_repo_into(d, str(repo_root / ".git"))

        features = get_features(str(manifest_path))
        combos = compute_powerset(features)
        total = len(combos)
        log(f"Total combinations: {total}")

        for combo in combos:
            retry_queue.put(combo)

        threads = []
        for i in range(args.thread_count):
            t = threading.Thread(target=worker_thread,
                                 args=(i, thread_dirs[i], manifest_rel, failure_log_path),
                                 daemon=True)
            t.start()
            threads.append(t)

        progress_thread = threading.Thread(target=progress_watcher, args=(total,), daemon=True)
        progress_thread.start()

        for t in threads:
            t.join()
        progress_thread.join()

    finally:
        stop_all_units()
        log("\nAll threads completed.")
        if failure_count > 0:
            log(f"{failure_count} combinations failed. See: {failure_log_path}")
        else:
            log("All combinations passed!")
        log(f"Temporary work directory preserved at: {base_temp}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_event.set()
        stop_all_units()
        log("\nForce exit requested. Exiting.")
