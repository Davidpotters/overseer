"""Overseer's demo target: a small program that makes a fixed, known set
of tool calls, so Monitor has something real to observe. This first pass
only exercises the allowed/normal path -- misbehave mode is added later,
once this container's own sandbox has been adversarially tested and
confirmed to hold.
"""

import os
import socket
import subprocess
import sys
import time

SCRATCH_DIR = os.environ.get("SCRATCH_DIR", "/scratch")
NOTE_PATH = os.path.join(SCRATCH_DIR, "agent.log")
ITERATIONS = int(os.environ.get("ITERATIONS", "5"))
LOOP_DELAY_SECONDS = float(os.environ.get("LOOP_DELAY_SECONDS", "2"))


def write_note(iteration: int) -> None:
    with open(NOTE_PATH, "a") as f:
        f.write(f"iteration {iteration}: agent wrote a note\n")
    print(f"[tool call] wrote note to {NOTE_PATH}", flush=True)


def read_note() -> None:
    with open(NOTE_PATH) as f:
        lines = f.readlines()
    print(f"[tool call] read back {len(lines)} line(s) from {NOTE_PATH}", flush=True)


def run_allowed_command() -> None:
    result = subprocess.run(
        ["echo", "tool-call-ok"], capture_output=True, text=True, timeout=5
    )
    print(f"[tool call] subprocess exec: {result.stdout.strip()}", flush=True)


def attempt_network_call() -> None:
    host = os.environ.get("NETWORK_TARGET_HOST", "decoy.invalid")
    port = int(os.environ.get("NETWORK_TARGET_PORT", "8080"))
    try:
        with socket.create_connection((host, port), timeout=2):
            print(f"[tool call] connected to {host}:{port}", flush=True)
    except OSError as exc:
        print(f"[tool call] network call to {host}:{port} failed as expected: {exc}", flush=True)


def main() -> None:
    os.makedirs(SCRATCH_DIR, exist_ok=True)
    print(f"agent starting, scratch dir = {SCRATCH_DIR}", flush=True)
    for i in range(1, ITERATIONS + 1):
        write_note(i)
        read_note()
        run_allowed_command()
        attempt_network_call()
        time.sleep(LOOP_DELAY_SECONDS)
    print("agent finished normal run", flush=True)


if __name__ == "__main__":
    sys.exit(main())
