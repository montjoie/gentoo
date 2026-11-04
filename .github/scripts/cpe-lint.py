#!/usr/bin/env python3
"""Lint CPE <remote-id> entries added/changed in metadata.xml files.

Fork-only CI helper; never submit this file upstream.

Usage:
    cpe-lint.py --base <git-ref> [--allow-23] [--nvd] [--github]

Checks (errors unless noted):
  * CPE syntax: repo convention is the CPE 2.2 URI form
    "cpe:/<part>:<vendor>:<product>" (lowercase, no version).
    cpe:2.3 formatted strings are rejected unless --allow-23 is given.
  * duplicate CPE within one metadata.xml
  * cpe:/o: or cpe:/h: parts (warning: only for OS / hardware firmware)
  * same CPE used by another package in the tree (warning)
  * --nvd: vendor:product unknown to NVD CPE dictionary (warning)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

COMPONENT = r"(?:[a-z0-9._~-]|%[0-9a-fA-F]{2})+"
CPE22_RE = re.compile(rf"^cpe:/([aho]):({COMPONENT}):({COMPONENT})$")
# vendor:product only, remaining 9 fields must be wildcards
CPE23_RE = re.compile(
    r"^cpe:2\.3:([aho]):((?:[a-z0-9._~-]|\\.)+):((?:[a-z0-9._~-]|\\.)+)"
    r"(?::\*){8}$"
)
CPE_ANY_RE = re.compile(r'<remote-id\s+type="cpe"\s*>\s*([^<]*?)\s*</remote-id>')
NVD_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class Report:
    def __init__(self, github: bool):
        self.github = github
        self.errors = 0
        self.warnings = 0

    def _emit(self, level: str, path: str, line: int | None, msg: str):
        if self.github:
            loc = f"file={path}" + (f",line={line}" if line else "")
            print(f"::{level} {loc}::{msg}")
        else:
            print(f"{level.upper()}: {path}{':' + str(line) if line else ''}: {msg}")

    def error(self, path, line, msg):
        self.errors += 1
        self._emit("error", path, line, msg)

    def warning(self, path, line, msg):
        self.warnings += 1
        self._emit("warning", path, line, msg)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def changed_metadata(base: str) -> list[str]:
    out = git("diff", "--name-only", "--diff-filter=AMR", f"{base}...HEAD",
              "--", "*/*/metadata.xml")
    return [p for p in out.splitlines() if p.count("/") == 2]


def cpes_in_text(text: str) -> list[tuple[str, int]]:
    """Return (cpe, line number) pairs."""
    res = []
    for m in CPE_ANY_RE.finditer(text):
        res.append((m.group(1), text.count("\n", 0, m.start()) + 1))
    return res


def old_cpes(base: str, path: str) -> set[str]:
    try:
        text = subprocess.run(["git", "show", f"{base}:{path}"], check=True,
                              capture_output=True, text=True).stdout
    except subprocess.CalledProcessError:
        return set()
    return {c for c, _ in cpes_in_text(text)}


def parse_cpe(cpe: str, allow_23: bool):
    """Return (part, vendor, product) or None; vendor/product unescaped."""
    m = CPE22_RE.match(cpe)
    if m:
        part, v, p = m.groups()
        return part, urllib.parse.unquote(v), urllib.parse.unquote(p)
    if allow_23:
        m = CPE23_RE.match(cpe)
        if m:
            part, v, p = m.groups()
            return part, re.sub(r"\\(.)", r"\1", v), re.sub(r"\\(.)", r"\1", p)
    return None


def explain_bad(cpe: str, allow_23: bool) -> str:
    if cpe != cpe.strip() or " " in cpe:
        return "contains whitespace"
    if cpe.lower() != cpe:
        return "must be lowercase"
    if cpe.startswith("cpe:2.3:") and not allow_23:
        parts = cpe.split(":")
        hint = (f"cpe:/{parts[2]}:{parts[3]}:{parts[4]}" if len(parts) >= 5
                else "cpe:/a:<vendor>:<product>")
        return f"repo convention is CPE 2.2 URI form, e.g. '{hint}'"
    if cpe.startswith("cpe:/") and cpe.count(":") > 3:
        return "only part:vendor:product is allowed (no version/update fields)"
    return "invalid syntax, expected cpe:/<a|o|h>:<vendor>:<product>"


def tree_cpe_index(repo: Path) -> dict[str, set[str]]:
    index: dict[str, set[str]] = defaultdict(set)
    for md in repo.glob("*/*/metadata.xml"):
        try:
            text = md.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if 'type="cpe"' not in text:
            continue
        pkg = f"{md.parent.parent.name}/{md.parent.name}"
        for cpe, _ in cpes_in_text(text):
            index[cpe].add(pkg)
    return index


def to_nvd_match(part: str, vendor: str, product: str) -> str:
    def esc(s):
        return re.sub(r"([^A-Za-z0-9_])", r"\\\1", s)
    return f"cpe:2.3:{part}:{esc(vendor)}:{esc(product)}:*:*:*:*:*:*:*:*"


def nvd_known(match: str, api_key: str | None, cache: dict) -> bool | None:
    if match in cache:
        return cache[match]
    url = f"{NVD_API}?{urllib.parse.urlencode({'cpeMatchString': match, 'resultsPerPage': 1})}"
    req = urllib.request.Request(url, headers={"User-Agent": "cpe-lint-ci"})
    if api_key:
        req.add_header("apiKey", api_key)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                total = json.load(r).get("totalResults", 0)
            cache[match] = total > 0
            break
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                time.sleep(10 * (attempt + 1))
                continue
            return None
        except (urllib.error.URLError, TimeoutError, ValueError):
            time.sleep(5)
    else:
        return None
    # public rate limit: 5 req / 30s, with key 50 req / 30s
    time.sleep(0.7 if api_key else 6.5)
    return cache[match]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="git ref to diff against")
    ap.add_argument("--allow-23", action="store_true",
                    help="also accept cpe:2.3 formatted strings")
    ap.add_argument("--nvd", action="store_true",
                    help="check vendor:product against NVD (warnings only)")
    ap.add_argument("--nvd-cache", default=".cpe-nvd-cache.json")
    ap.add_argument("--github", action="store_true",
                    help="emit GitHub workflow annotations")
    args = ap.parse_args()

    rep = Report(args.github)
    repo = Path(git("rev-parse", "--show-toplevel").strip())
    os.chdir(repo)

    files = changed_metadata(args.base)
    print(f"{len(files)} changed metadata.xml file(s)")

    new_entries = []  # (path, line, cpe, parsed)
    for path in files:
        text = Path(path).read_text(encoding="utf-8")
        try:
            ET.fromstring(text.encode())
        except ET.ParseError as e:
            rep.error(path, None, f"XML parse error: {e}")
            continue
        # also catch cpe remote-ids the regex would miss (odd formatting)
        root = ET.fromstring(text.encode())
        n_xml = sum(1 for r in root.iter("remote-id") if r.get("type") == "cpe")
        found = cpes_in_text(text)
        if n_xml != len(found):
            rep.error(path, None, "unusual <remote-id type=\"cpe\"> formatting, "
                      "use <remote-id type=\"cpe\">VALUE</remote-id> on one line")

        before = old_cpes(args.base, path)
        seen = {}
        for cpe, line in found:
            if cpe in seen:
                rep.error(path, line, f"duplicate CPE {cpe} (first at line {seen[cpe]})")
                continue
            seen[cpe] = line
            if cpe in before:
                continue  # pre-existing, not our business
            parsed = parse_cpe(cpe, args.allow_23)
            if parsed is None:
                rep.error(path, line, f"{cpe}: {explain_bad(cpe, args.allow_23)}")
                continue
            if parsed[0] in "oh":
                rep.warning(path, line, f"{cpe}: part '{parsed[0]}' is for OS/hardware; "
                            "applications use 'a'")
            new_entries.append((path, line, cpe, parsed))

    if new_entries:
        index = tree_cpe_index(repo)
        for path, line, cpe, _ in new_entries:
            pkg = "/".join(path.split("/")[:2])
            others = sorted(index.get(cpe, set()) - {pkg})
            if others:
                rep.warning(path, line, f"{cpe} also used by: {', '.join(others)}")

    if args.nvd and new_entries:
        cache_file = Path(args.nvd_cache)
        try:
            cache = json.loads(cache_file.read_text())
        except (OSError, ValueError):
            cache = {}
        api_key = os.environ.get("NVD_API_KEY") or None
        for path, line, cpe, (part, vendor, product) in new_entries:
            known = nvd_known(to_nvd_match(part, vendor, product), api_key, cache)
            if known is False:
                rep.warning(path, line, f"{cpe}: not found in NVD CPE dictionary "
                            "(typo? or no CVE history yet)")
            elif known is None:
                rep.warning(path, line, f"{cpe}: NVD lookup failed, not verified")
        cache_file.write_text(json.dumps(cache, indent=1, sort_keys=True))

    print(f"{len(new_entries)} new CPE(s), {rep.errors} error(s), {rep.warnings} warning(s)")
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
