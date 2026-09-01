#!/usr/bin/env python3
"""Blind-description training pass: first 25 published CVE-2026-* vs NVD gold."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

from vulnavigator.artifacts import cwes_from_text
from vulnavigator.pipeline import analyze_text

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CWE_RE = re.compile(r"CWE-\d+", re.I)
FILE_RE = re.compile(
    r"(?:^|[^\w./])((?:/[A-Za-z0-9_.-]+)+\.[A-Za-z0-9]+|(?:[A-Za-z0-9_.-]+/)+\.[A-Za-z0-9]+|[A-Za-z0-9_.-]+\.(?:php|asp|aspx|jsp|py|js|ts|go|c|cc|cpp|cxx|h|hh|hpp|java|rb|cgi))(?!\w)",
    re.I,
)
SQLI_RE = re.compile(r"\bsql\s*injection\b|\bCWE-89\b", re.I)
XSS_RE = re.compile(r"\bcross[-\s]?site scripting\b|\bxss\b|\bCWE-79\b", re.I)
RCE_RE = re.compile(r"\bremote\s+c[oa]de\s+execution\b|\brce\b|\bCWE-94\b", re.I)
REMOTE_RE = re.compile(
    r"\bremotely\b|\bremote\s+attacker\b|\battack remotely\b|\bunauthenticated remote\b|"
    r"\binternet[-\s]?facing\b|\bpublic[-\s]?facing\b|"
    r"\bfrom remote\b|\blaunched remotely\b|\bperformed from remote\b|"
    r"\bunauthenticated attacker\b",
    re.I,
)
EXPLOIT_RE = re.compile(
    r"exploit has been (?:released|disclosed|published)|public(?:ly)? (?:available )?exploit|"
    r"poc (?:is|has been) (?:available|released)",
    re.I,
)

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def nvd_key() -> str:
    path = Path.home() / ".discover" / "api-keys"
    if os.environ.get("SUDO_USER"):
        path = Path("/home") / os.environ["SUDO_USER"] / ".discover" / "api-keys"
    if not path.is_file():
        path = Path("/home/iceroot/.discover/api-keys")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == "NVD_API_KEY":
            return v.strip().split()[0]
    return os.environ.get("NVD_API_KEY", "")


def get_json(url: str, key: str) -> dict:
    headers = {"User-Agent": "VulNavigator-training/0.1", "Accept": "application/json"}
    if key:
        headers["apiKey"] = key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=40) as resp:
        return json.loads(resp.read().decode("utf-8"))


def en_desc(cve: dict) -> str:
    for row in cve.get("descriptions") or []:
        if row.get("lang") == "en":
            return (row.get("value") or "").strip()
    return ""


def gold_cwes(cve: dict) -> list[str]:
    out: list[str] = []
    for weak in cve.get("weaknesses") or []:
        for desc in weak.get("description") or []:
            val = str(desc.get("value") or "").upper()
            if val.startswith("CWE-") and val not in out and val != "NVD-CWE-NOINFO":
                out.append(val)
    return out


def gold_cvss(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if not rows:
            continue
        data = rows[0].get("cvssData") or {}
        score = data.get("baseScore")
        vec = str(data.get("vectorString") or "")
        if score is not None:
            return float(score), vec
    return None, ""


def gold_products(cve: dict) -> list[str]:
    names: list[str] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                cpe = str(match.get("criteria") or "")
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    label = f"{vendor}:{product}".replace("_", " ")
                    if label not in names:
                        names.append(label)
    return names


def av_network(vec: str) -> bool:
    return "AV:N" in vec or "/AV:N/" in vec


def fetch_first_n(key: str, limit: int = 25) -> list[dict]:
    found: list[dict] = []
    seen: set[str] = set()
    # NVD rejects pub-date windows longer than 120 days.
    windows = (
        ("2026-01-01T00:00:00.000", "2026-03-31T23:59:59.000"),
        ("2026-04-01T00:00:00.000", "2026-06-29T23:59:59.000"),
        ("2026-06-30T00:00:00.000", "2026-09-01T23:59:59.000"),
    )
    for start_d, end_d in windows:
        start = 0
        while len(found) < limit:
            q = {
                "pubStartDate": start_d,
                "pubEndDate": end_d,
                "resultsPerPage": 200,
                "startIndex": start,
            }
            url = NVD + "?" + urllib.parse.urlencode(q)
            data = get_json(url, key)
            rows = data.get("vulnerabilities") or []
            if not rows:
                break
            for item in rows:
                cve = item.get("cve") or {}
                cid = str(cve.get("id") or "")
                status = str(cve.get("vulnStatus") or "")
                if not cid.startswith("CVE-2026-"):
                    continue
                if status.lower() == "rejected":
                    continue
                if not en_desc(cve):
                    continue
                if cid in seen:
                    continue
                seen.add(cid)
                found.append(cve)
                if len(found) >= limit:
                    break
            start += len(rows)
            total = int(data.get("totalResults") or 0)
            if start >= total:
                break
            time.sleep(0.6)
        if len(found) >= limit:
            break
    return found[:limit]


def blind_text(desc: str) -> str:
    return CVE_RE.sub("[ID REDACTED]", desc).strip()


def issues_for(cve: dict, case) -> list[str]:
    cid = cve.get("id")
    desc = en_desc(cve)
    cwes = gold_cwes(cve)
    cvss, vec = gold_cvss(cve)
    products = gold_products(cve)
    files = [m.group(1) for m in FILE_RE.finditer(desc)]
    out: list[str] = []

    if case.cves:
        out.append(f"LEAK: invented/kept CVE {case.cves} (input had no CVE id)")
    if "cve" in (case.source_kind or "").lower() and not case.cves:
        out.append("source_kind=cve without an id")
    notes = " ".join(case.validation_notes or [])
    if "No CVE expected" in notes or "AI 0-day identity" in notes:
        out.append("CONFLICT: treated as AI 0-day / no-CVE-expected (this is an NVD advisory)")

    if SQLI_RE.search(desc) and not any(c.startswith("CWE-89") for c in case.cwes):
        out.append("MISSING: sql injection in description but no CWE-89")
    if XSS_RE.search(desc) and not any(c.startswith("CWE-79") for c in case.cwes):
        out.append("MISSING: XSS in description but no CWE-79")
    if RCE_RE.search(desc) and not any(c.startswith("CWE-94") for c in case.cwes):
        exec_ids = ("T1059", "T1190", "T1203", "T1068")
        if not any(any(tag in (m.id or "") for tag in exec_ids) for m in case.attack):
            out.append("MISSING: RCE language but no CWE-94 / execution ATT&CK")

    gold_cwe_set = {c for c in cwes if c.startswith("CWE-")}
    buffer = {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787"}
    cmd = {"CWE-74", "CWE-77", "CWE-78"}
    auth = {"CWE-284", "CWE-285", "CWE-287", "CWE-288", "CWE-290", "CWE-306", "CWE-862", "CWE-863"}
    uaf = {"CWE-415", "CWE-416"}
    info = {"CWE-200", "CWE-201", "CWE-497"}
    cleartext = {"CWE-261", "CWE-319", "CWE-497", "CWE-522"}
    resource = {"CWE-400", "CWE-409", "CWE-674", "CWE-770", "CWE-772", "CWE-789"}
    got = set(case.cwes)
    related = any(
        gold_cwe_set & family and got & family
        for family in (buffer, cmd, auth, uaf, info, cleartext, resource)
    )
    taught = set(cwes_from_text(desc))
    gold_specific = gold_cwe_set - {"CWE-20"}
    phrase_ok = bool(taught) and taught <= got
    if taught - got:
        out.append(f"MISSING: phrase CWE {sorted(taught - got)} not on case {case.cwes}")
    elif gold_specific and not (gold_specific & got) and not related and taught and not phrase_ok:
        out.append(f"MISSING: NVD CWE {sorted(gold_cwe_set)} not on case {case.cwes}")

    if REMOTE_RE.search(desc) and case.asset_internet_facing is not True:
        out.append("MISSING: remote language in description but internet_facing is not True")

    if files and not case.locations and not case.endpoint:
        shown = ", ".join(files[:3])
        out.append(f"MISSING: file path in description ({shown}) not extracted")

    if case.product:
        blob = (desc + " " + " ".join(products)).lower()
        if case.product.lower() not in blob and case.product.lower() in {
            "system",
            "server",
            "manager",
            "service",
            "application",
            "software",
            "version",
            "plugin",
            "module",
            "index",
            "file",
        }:
            out.append(f"CONFLICT: product truncated to {case.product!r} (NVD products {products[:2] or 'from description'})")
    elif products:
        generic = {
            "firmware",
            "software",
            "plugin",
            "extension",
            "android",
            "system",
            "server",
            "manager",
            "application",
            "library",
            "tools",
            "data",
            "page",
            "css",
            "mediawiki",
            "connect",
            "station",
            "lite",
            "project",
            "open",
            "source",
        }
        named = " ".join(products).replace(":", " ")
        tokens = [
            part
            for part in named.split()
            if len(part) > 4 and part.lower() not in generic and part.lower() in desc.lower()
        ]
        if tokens:
            out.append(f"MISSING: product/version named in description (NVD CPE {products[:2]})")

    if EXPLOIT_RE.search(desc) and not (
        (case.evidence.poc or "").strip() or "public exploit" in (case.evidence.notes or "").lower()
    ):
        out.append("MISSING: public-exploit claim in description not recorded as evidence")

    if not case.attack and (case.cwes or taught):
        out.append("MISSING: empty ATT&CK map")

    if case.validation_status == "rejected":
        out.append("CONFLICT: rejected a published CVE description")

    # Blind pass should not get NVD CVSS; if it did, the CVE leaked.
    if case.cvss is not None:
        out.append(f"LEAK: CVSS {case.cvss} filled (should be blind to NVD)")

    return out


def _print_rows(rows: list[dict], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {dest} n={len(rows)}")
    clean = 0
    for row in rows:
        print("---", row["cve"], row["vn_kind"], row["vn_status"], row["vn_priority"], "issues", len(row["issues"]))
        for item in row["issues"]:
            print("   ", item)
        if not row["issues"]:
            clean += 1
    print(f"CLEAN {clean}/{len(rows)}")


def _configs_from_products(products: list[str]) -> list:
    nodes = []
    for label in products:
        if ":" in label:
            vendor, product = label.split(":", 1)
        else:
            vendor, product = "unknown", label
        cpe = (
            f"cpe:2.3:a:{vendor.replace(' ', '_')}:{product.replace(' ', '_')}"
            f":*:*:*:*:*:*:*:*"
        )
        nodes.append({"cpeMatch": [{"criteria": cpe}]})
    return [{"nodes": nodes}] if nodes else []


def _products_from_score_row(row: dict) -> list[str]:
    if row.get("nvd_products"):
        return list(row["nvd_products"])
    for item in row.get("issues") or []:
        match = re.search(r"NVD CPE (\[.*\])$", item)
        if not match:
            continue
        try:
            parsed = json.loads(match.group(1).replace("'", '"'))
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, list):
            return [str(p) for p in parsed]
    return []


def _row_for(cve: dict, case, blind: str, products: list[str] | None = None) -> dict:
    cvss, _vec = gold_cvss(cve)
    return {
        "cve": cve.get("id"),
        "published": cve.get("published"),
        "nvd_cwe": gold_cwes(cve),
        "nvd_cvss": cvss,
        "nvd_products": products if products is not None else gold_products(cve),
        "vn_kind": case.source_kind,
        "vn_status": case.validation_status,
        "vn_priority": case.priority,
        "vn_product": case.product,
        "vn_version": case.version,
        "vn_cwes": case.cwes,
        "vn_cves": case.cves,
        "vn_attack": [m.id for m in case.attack],
        "vn_facing": case.asset_internet_facing,
        "issues": issues_for(cve, case),
        "blind": blind[:220],
    }


def rescore(limit: int = 300) -> None:
    """Re-analyze the frozen corpus against stored NVD gold (no NVD fetch)."""
    root = Path(__file__).resolve().parents[2]
    corpus_path = Path(__file__).resolve().parents[1] / "data" / "blind_cve_2026.json"
    dest = root / "cases" / f"blind-first-{limit}.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))[:limit]
    old_rows = {}
    if dest.exists():
        for row in json.loads(dest.read_text(encoding="utf-8")):
            old_rows[str(row.get("cve"))] = row
    rows = []
    for item in corpus:
        cid = item["cve"]
        desc = item["description"]
        old = old_rows.get(cid, {})
        products = _products_from_score_row(old)
        cve = {
            "id": cid,
            "published": old.get("published"),
            "descriptions": [{"lang": "en", "value": desc}],
            "weaknesses": [
                {"description": [{"value": c} for c in (item.get("nvd_cwe") or old.get("nvd_cwe") or [])]}
            ],
            "metrics": {},
            "configurations": _configs_from_products(products),
        }
        case = analyze_text(desc, offline=True)[0]
        rows.append(_row_for(cve, case, desc, products=products))
    _print_rows(rows, dest)


def main() -> None:
    import sys

    args = [a for a in sys.argv[1:] if a != "--rescan"]
    rescan = "--rescan" in sys.argv[1:]
    limit = int(args[0]) if args else 50
    if rescan:
        rescore(limit)
        return
    key = nvd_key()
    gold = fetch_first_n(key, limit)
    rows = []
    corpus = []
    for cve in gold:
        cid = cve["id"]
        desc = en_desc(cve)
        blind = blind_text(desc)
        case = analyze_text(blind, offline=True)[0]
        rows.append(_row_for(cve, case, blind))
        corpus.append(
            {
                "cve": cid,
                "description": blind,
                "nvd_cwe": gold_cwes(cve),
                "nvd_cvss": gold_cvss(cve)[0],
            }
        )
    dest = Path(__file__).resolve().parents[2] / "cases" / f"blind-first-{limit}.json"
    corpus_path = Path(__file__).resolve().parents[1] / "data" / "blind_cve_2026.json"
    corpus_path.parent.mkdir(parents=True, exist_ok=True)
    corpus_path.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {corpus_path}")
    _print_rows(rows, dest)


if __name__ == "__main__":
    main()
