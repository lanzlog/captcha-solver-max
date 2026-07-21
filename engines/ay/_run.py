"""Standalone subprocess runner for run_ay.

WHY a subprocess: the drag trajectory depends on precise CDP Input.dispatchMouseEvent
timing, and that timing is fidelity-sensitive to running on the MAIN thread with a clean
event loop. Proven empirically:
  - asyncio.run(run_ay()) on the main thread  -> 3/3 T001
  - awaited directly on uvicorn's loop               -> 0/12 F001
  - asyncio.run(...) inside asyncio.to_thread worker -> 0/12 F001 (off-main-thread)
So the server dispatches aliyun to THIS script as its own process: its main thread runs
asyncio.run, exactly reproducing the working direct-call conditions. Prints a single JSON
line to stdout.

Usage: python -m engines.ay._run <scene_id> <prefix> <region> <timeout_s> [proxy]
"""
import asyncio
import json
import sys

from engines.ay.runner import run_ay


def main():
    scene_id = sys.argv[1]
    prefix = sys.argv[2]
    region = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else "sgp"
    timeout_s = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else 90
    proxy = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
    try:
        r = asyncio.run(run_ay(
            scene_id=scene_id, prefix=prefix, region=region,
            proxy=proxy, timeout_s=timeout_s))
    except Exception as e:
        r = {"solved": False, "error": f"runner: {e}"}
    # single JSON line on the last line of stdout (solver logs go to stderr/logging above)
    print("__ALIYUN_RESULT__" + json.dumps(r), flush=True)


if __name__ == "__main__":
    main()
