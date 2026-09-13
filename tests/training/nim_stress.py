#!/usr/bin/env python3
"""Measure NVIDIA NIM throughput for this account. Stops on 429/401/403.

  .venv/bin/python tests/training/nim_stress.py --ping --n 40
  .venv/bin/python tests/training/nim_stress.py --ping --n 20 --concurrency 5
  .venv/bin/python tests/training/nim_stress.py --suggest --n 5
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import importlib.util
import sys

_HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("nim_suggest", _HERE / "nim_suggest.py")
_ns = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
sys.modules["nim_suggest"] = _ns
_spec.loader.exec_module(_ns)
api_key = _ns.api_key
DEFAULT_BASE = _ns.DEFAULT_BASE
DEFAULT_MODEL = _ns.DEFAULT_MODEL
parse_pack = _ns.parse_pack
suggest_one = _ns.suggest_one


PING_PACK = """\
### CVE-2026-0544
nvd=['CWE-89'] vn=[] product='School Management System'
- MISSING: phrase CWE ['CWE-89'] not on case []

The manipulation of the argument ID results in sql injection. It is possible to launch the attack remotely.
"""


def ping_once(key: str, model: str, base: str, timeout: int = 60) -> tuple[int, float, str]:
    t0 = time.perf_counter()
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with the single digit 1."}],
            "temperature": 0,
            "max_tokens": 8,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        base.rstrip("/") + "/chat/completions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": "VulNavigator-nim-stress/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            code = resp.status
            detail = "ok"
    except urllib.error.HTTPError as exc:
        code = exc.code
        detail = exc.read().decode("utf-8", errors="replace")[:120].replace("\n", " ")
    except Exception as exc:  # noqa: BLE001
        code = 0
        detail = type(exc).__name__
    return code, time.perf_counter() - t0, detail


def summarize(rows: list[tuple[int, float, str]]) -> None:
    ok = [r for r in rows if r[0] == 200]
    print(f"n={len(rows)}  http200={len(ok)}  other={len(rows) - len(ok)}")
    codes: dict[int, int] = {}
    for code, _, _ in rows:
        codes[code] = codes.get(code, 0) + 1
    print("codes", dict(sorted(codes.items())))
    if ok:
        lat = [r[1] for r in ok]
        span = sum(r[1] for r in rows) or 1.0
        print(
            f"latency_s min={min(lat):.2f} median={statistics.median(lat):.2f} "
            f"max={max(lat):.2f}"
        )
        wall = rows[-1][1] if False else None
        _ = wall
    first = rows[0][1] if rows else 0
    # caller prints wall clock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ping", action="store_true")
    parser.add_argument("--suggest", action="store_true")
    parser.add_argument("--n", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--stop-on-limit", action="store_true", default=True)
    args = parser.parse_args()
    if not args.ping and not args.suggest:
        args.ping = True
    key = api_key()
    if not key:
        raise SystemExit("missing NVIDIA_API_KEY")
    model = DEFAULT_MODEL
    base = DEFAULT_BASE
    n = max(1, args.n)
    conc = max(1, args.concurrency)
    print(
        f"model={model} n={n} concurrency={conc} mode={'suggest' if args.suggest else 'ping'}",
        flush=True,
    )

    rows: list[tuple[int, float, str]] = []
    t_wall = time.perf_counter()
    stop = False

    if args.ping:
        def job(_i: int) -> tuple[int, float, str]:
            return ping_once(key, model, base)

        if conc == 1:
            for i in range(n):
                if stop:
                    break
                rec = job(i)
                rows.append(rec)
                print(f"  {i+1:03d}  HTTP {rec[0]}  {rec[1]:.2f}s  {rec[2][:80]}", flush=True)
                if rec[0] in {401, 403, 429} and args.stop_on_limit:
                    print("stop: rate/auth limit")
                    stop = True
        else:
            with ThreadPoolExecutor(max_workers=conc) as pool:
                futs = [pool.submit(job, i) for i in range(n)]
                for i, fut in enumerate(as_completed(futs), 1):
                    rec = fut.result()
                    rows.append(rec)
                    print(f"  {i:03d}  HTTP {rec[0]}  {rec[1]:.2f}s  {rec[2][:80]}")
                    if rec[0] in {401, 403, 429} and args.stop_on_limit:
                        stop = True

    if args.suggest:
        sample = parse_pack(PING_PACK)[0]
        def sjob(_i: int) -> tuple[int, float, str]:
            t0 = time.perf_counter()
            try:
                out = suggest_one(sample, key=key, model=model, base=base)
                kept = len(out.get("kept") or [])
                rej = len(out.get("rejected") or [])
                return 200, time.perf_counter() - t0, f"kept={kept} rejected={rej}"
            except RuntimeError as exc:
                msg = str(exc)
                code = 0
                if "HTTP 429" in msg:
                    code = 429
                elif "HTTP 401" in msg:
                    code = 401
                elif "HTTP 403" in msg:
                    code = 403
                elif "HTTP " in msg:
                    try:
                        code = int(msg.split("HTTP ", 1)[1].split(":", 1)[0])
                    except ValueError:
                        code = 0
                return code, time.perf_counter() - t0, msg[:120]
            except Exception as exc:  # noqa: BLE001
                return 0, time.perf_counter() - t0, type(exc).__name__

        if conc == 1:
            for i in range(n):
                rec = sjob(i)
                rows.append(rec)
                print(f"  {i+1:03d}  HTTP {rec[0]}  {rec[1]:.2f}s  {rec[2][:80]}", flush=True)
                if rec[0] in {401, 403, 429} and args.stop_on_limit:
                    print("stop: rate/auth limit")
                    break
        else:
            with ThreadPoolExecutor(max_workers=conc) as pool:
                futs = [pool.submit(sjob, i) for i in range(n)]
                for i, fut in enumerate(as_completed(futs), 1):
                    rec = fut.result()
                    rows.append(rec)
                    print(f"  {i:03d}  HTTP {rec[0]}  {rec[1]:.2f}s  {rec[2][:80]}")

    wall = time.perf_counter() - t_wall
    ok_n = sum(1 for r in rows if r[0] == 200)
    print("---")
    summarize(rows)
    print(f"wall_s={wall:.1f}  implied_rpm={ok_n / (wall / 60) if wall else 0:.1f}")
    return 0 if ok_n else 1


if __name__ == "__main__":
    raise SystemExit(main())
