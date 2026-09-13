#!/usr/bin/env python3
"""Draft phrase → CWE rules from the weekly error pack via NVIDIA NIM.

Does not run analyze, does not write phrase_cwe.py. Prints JSON candidates.
Local gates: pattern must match the sample; CWE must be CWE-*; family must be
known; NVD-only labels and AI 0-day claims are rejected.

  NVIDIA_API_KEY or NGC_API_KEY, or NVIDIA_API_KEY= in ~/.discover/api-keys
  NVIDIA_NIM_MODEL  default meta/llama-3.3-70b-instruct
  NVIDIA_NIM_BASE   default https://integrate.api.nvidia.com/v1

  .venv/bin/python tests/training/nim_suggest.py --dry-run
  .venv/bin/python tests/training/nim_suggest.py --limit 5
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from vulnavigator.data.phrase_cwe import FAMILIES, PHRASE_CWE_RULES

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_PACK = ROOT / "cases" / "error-pack.md"
DEFAULT_BASE = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "deepseek-ai/deepseek-v4-flash-0731"

CVE_HEAD = re.compile(r"^###\s+(CVE-\d{4}-\d{4,})\s*$", re.I)
CWE_RE = re.compile(r"^CWE-\d+$", re.I)
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")

SYSTEM = """\
You draft phrase → CWE extractor rules for VulNavigator from one NVD English
description with the CVE id already stripped from analysis.

Rules:
- Teach only phrases present in the sample text.
- Phrase → CWE, not NVD-only labels (ignore CWE-20 / CWE-other if the prose
  never names that class).
- A pasted advisory without a CVE id is not an AI 0-day. Never suggest that.
- Do not invent products, paths, or CVEs.
- If nothing in the prose implies a new CWE, return {"suggestions": [], "skip": "reason"}.

Return JSON only:
{"suggestions":[{"id":"kebab-id","family":"injection","cwe":"CWE-89",
"pattern":"sql\\\\s*injection","quote":"exact words from the sample",
"owner":"narrative","reason":"short"}],"skip":""}

family must be one of: """ + ", ".join(FAMILIES)


def api_key() -> str:
    env = (os.environ.get("NVIDIA_API_KEY") or os.environ.get("NGC_API_KEY") or "").strip()
    if env:
        return env.split()[0]
    path = Path.home() / ".discover" / "api-keys"
    if os.environ.get("SUDO_USER"):
        path = Path("/home") / os.environ["SUDO_USER"] / ".discover" / "api-keys"
    if not path.is_file():
        path = Path("/home/iceroot/.discover/api-keys")
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() in {"NVIDIA_API_KEY", "NGC_API_KEY"}:
            return v.strip().split()[0]
    return ""


def parse_pack(text: str) -> list[dict[str, Any]]:
    """Pull ### CVE samples from error-pack.md."""
    samples: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    body: list[str] = []
    issues: list[str] = []
    nvd = ""
    vn = ""
    product = ""

    def flush() -> None:
        nonlocal current, body, issues, nvd, vn, product
        if not current:
            return
        desc = "\n".join(body).strip()
        if desc or issues:
            current.update(
                {
                    "description": desc,
                    "issues": list(issues),
                    "nvd_cwe": nvd,
                    "vn_cwes": vn,
                    "product": product,
                }
            )
            samples.append(current)
        current = None
        body = []
        issues = []
        nvd = vn = product = ""

    for line in text.splitlines():
        m = CVE_HEAD.match(line)
        if m:
            flush()
            current = {"cve": m.group(1).upper()}
            continue
        if current is None:
            continue
        if line.startswith("## "):
            flush()
            continue
        if line.startswith("nvd="):
            nvd = line
            continue
        if line.startswith("- "):
            issues.append(line[2:].strip())
            continue
        if line.strip():
            body.append(line)
    flush()
    return samples


def _strip_fences(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_model_json(raw: str) -> dict[str, Any]:
    text = _strip_fences(raw)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        data = json.loads(m.group(0))
    if not isinstance(data, dict):
        raise ValueError("model JSON must be an object")
    sugg = data.get("suggestions")
    if sugg is None:
        sugg = []
    if not isinstance(sugg, list):
        raise ValueError("suggestions must be a list")
    data["suggestions"] = sugg
    data["skip"] = str(data.get("skip") or "")
    return data


def validate_candidate(sample: dict[str, Any], row: dict[str, Any]) -> list[str]:
    """Return reject reasons. Empty list = keep."""
    reasons: list[str] = []
    desc = sample.get("description") or ""
    cid = str(row.get("id") or "").strip()
    family = str(row.get("family") or "").strip()
    cwe = str(row.get("cwe") or "").strip().upper()
    pattern = str(row.get("pattern") or "")
    quote = str(row.get("quote") or "").strip()
    reason = (str(row.get("reason") or "") + " " + quote).lower()

    if not ID_RE.match(cid):
        reasons.append("bad id")
    if family not in FAMILIES:
        reasons.append(f"unknown family {family!r}")
    if not CWE_RE.match(cwe):
        reasons.append(f"bad cwe {cwe!r}")
    if "0-day" in reason or "zeroday" in reason.replace(" ", "") or "ai 0-day" in reason:
        reasons.append("ai-0day claim")
    if not pattern:
        reasons.append("empty pattern")
    else:
        try:
            compiled = re.compile(pattern, re.I)
        except re.error as exc:
            reasons.append(f"bad regex: {exc}")
            compiled = None
        if compiled is not None and desc and not compiled.search(desc):
            reasons.append("pattern does not match sample")
    if quote and desc and quote.lower() not in desc.lower():
        reasons.append("quote not in sample")
    nvd_blob = str(sample.get("nvd_cwe") or "")
    if (
        cwe
        and cwe in nvd_blob.upper()
        and desc
        and cwe.lower() not in desc.lower()
        and pattern
    ):
        # NVD gold on the header but CWE id never appears in prose: only keep if
        # the pattern actually matched words (already checked). If pattern is
        # just the CWE id, reject.
        if re.fullmatch(rf"CWE-\\d+|\\b{re.escape(cwe)}\\b", pattern, re.I):
            reasons.append("NVD-only CWE id pattern")
    existing = {r["id"] for r in PHRASE_CWE_RULES}
    if cid in existing:
        reasons.append("id already in phrase_cwe.py")
    return reasons


def user_prompt(sample: dict[str, Any]) -> str:
    issues = "\n".join(f"- {i}" for i in sample.get("issues") or []) or "- (none listed)"
    return (
        f"CVE id (context only, do not put in the rule): {sample.get('cve')}\n"
        f"{sample.get('nvd_cwe') or ''}\n"
        f"Issues:\n{issues}\n\n"
        f"Sample description:\n{sample.get('description') or ''}\n"
    )


def chat_completions(
    *,
    key: str,
    model: str,
    base: str,
    messages: list[dict[str, str]],
    timeout: int = 120,
) -> str:
    url = base.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 2048,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "VulNavigator-nim-suggest/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise RuntimeError(f"NIM HTTP {exc.code}: {detail}") from None
    choices = payload.get("choices") or []
    if not choices:
        raise ValueError(f"NIM empty choices: {payload!r}"[:400])
    msg = choices[0].get("message") or {}
    content = str(msg.get("content") or "").strip()
    if not content:
        content = str(msg.get("reasoning_content") or "").strip()
    return content


def suggest_one(
    sample: dict[str, Any],
    *,
    key: str,
    model: str,
    base: str,
    chat=chat_completions,
    timeout: int = 120,
) -> dict[str, Any]:
    raw = chat(
        key=key,
        model=model,
        base=base,
        messages=[
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user_prompt(sample)},
        ],
        timeout=timeout,
    )
    parsed = parse_model_json(raw)
    kept: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for row in parsed["suggestions"]:
        if not isinstance(row, dict):
            rejected.append({"row": row, "reasons": ["not an object"]})
            continue
        reasons = validate_candidate(sample, row)
        if reasons:
            rejected.append({"row": row, "reasons": reasons})
        else:
            kept.append(
                {
                    "id": row["id"],
                    "family": row["family"],
                    "cwe": str(row["cwe"]).upper(),
                    "pattern": row["pattern"],
                    "quote": row.get("quote") or "",
                    "owner": row.get("owner") or "narrative",
                    "reason": row.get("reason") or "",
                    "cve": sample.get("cve"),
                }
            )
    return {
        "cve": sample.get("cve"),
        "skip": parsed.get("skip") or "",
        "kept": kept,
        "rejected": rejected,
    }


def run(
    pack_text: str,
    *,
    key: str,
    model: str,
    base: str,
    limit: int = 0,
    sleep_s: float = 1.6,
    dry_run: bool = False,
    chat=chat_completions,
) -> dict[str, Any]:
    samples = parse_pack(pack_text)
    if limit:
        samples = samples[:limit]
    out: dict[str, Any] = {
        "model": model,
        "dry_run": dry_run,
        "samples": len(samples),
        "results": [],
    }
    if not samples:
        out["note"] = "no ### CVE samples in pack (clean scorecard is expected)"
        return out
    if dry_run:
        out["results"] = [
            {"cve": s.get("cve"), "issues": s.get("issues"), "chars": len(s.get("description") or "")}
            for s in samples
        ]
        return out
    if not key:
        raise SystemExit(
            "missing NVIDIA_API_KEY (env or ~/.discover/api-keys). Use --dry-run to parse only."
        )
    for i, sample in enumerate(samples):
        cid = sample.get("cve")
        print(f"NIM sample {i+1}/{len(samples)} {cid}", flush=True)
        try:
            out["results"].append(
                suggest_one(sample, key=key, model=model, base=base, chat=chat)
            )
        except (TimeoutError, RuntimeError, OSError, ValueError) as exc:
            out["results"].append(
                {
                    "cve": cid,
                    "skip": "",
                    "kept": [],
                    "rejected": [],
                    "error": f"{type(exc).__name__}: {exc}"[:240],
                }
            )
            print(f"  error {type(exc).__name__}", flush=True)
        else:
            last = out["results"][-1]
            print(
                f"  kept={len(last.get('kept') or [])} "
                f"rejected={len(last.get('rejected') or [])} "
                f"skip={last.get('skip') or '-'}",
                flush=True,
            )
        if i + 1 < len(samples) and sleep_s:
            time.sleep(sleep_s)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pack",
        type=Path,
        default=DEFAULT_PACK,
        help="error-pack.md (default cases/error-pack.md)",
    )
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--sleep", type=float, default=1.6)
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="write JSON (default stdout; cases/nim-suggest.json if set to that path)",
    )
    args = parser.parse_args(argv)
    if not args.pack.is_file():
        raise SystemExit(f"missing {args.pack} — run weekly.py --rescan first")
    model = os.environ.get("NVIDIA_NIM_MODEL") or DEFAULT_MODEL
    base = os.environ.get("NVIDIA_NIM_BASE") or DEFAULT_BASE
    report = run(
        args.pack.read_text(encoding="utf-8"),
        key=api_key(),
        model=model,
        base=base,
        limit=args.limit,
        sleep_s=args.sleep,
        dry_run=args.dry_run,
    )
    text = json.dumps(report, indent=2)
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}", flush=True)
    kept_n = sum(len(r.get("kept") or []) for r in report.get("results") or [] if isinstance(r, dict))
    if kept_n:
        print(
            f"kept={kept_n} candidate(s). Review, then add phrase_cwe.py + "
            "phrase_families.json; pytest -q; weekly.py --rescan.",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
