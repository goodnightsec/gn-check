#!/usr/bin/env python3
"""Summarise Trivy release scans for one image and fail on blocking findings.

The workflow runs two scans per platform:

* a gate scan with --ignore-unfixed and --exit-code 1; the scanner image also
  skips the bundled nuclei/naabu binaries
* a full scan without those filters, used for the run summary and the release
  notes that must name findings without a fix (SVT-6)

The gate report contains the blocking findings. The full report contains every
high and critical finding. The difference is accepted: either it has no fix, or
it is in the bundled nuclei/naabu binaries that the scanner gate skips.
"""

import argparse
import json
import os
import sys
from collections import defaultdict

SEVERITIES = ("CRITICAL", "HIGH")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def findings(report):
    rows = []
    for result in report.get("Results") or []:
        target = result.get("Target") or ""
        for vuln in result.get("Vulnerabilities") or []:
            if vuln.get("Severity") not in SEVERITIES:
                continue
            rows.append(
                {
                    "target": target,
                    "id": vuln.get("VulnerabilityID") or "",
                    "severity": vuln.get("Severity") or "",
                    "pkg": vuln.get("PkgName") or "",
                    "installed": vuln.get("InstalledVersion") or "",
                    "fixed": vuln.get("FixedVersion") or "",
                    "status": vuln.get("Status") or "",
                }
            )
    return rows


def key(row):
    return (row["target"], row["id"], row["pkg"], row["installed"])


def platform(report, path):
    arch = ((report.get("Metadata") or {}).get("ImageConfig") or {}).get("architecture")
    if arch:
        return arch
    name = os.path.basename(path)
    return name.rsplit("-", 1)[-1].removesuffix(".json")


def cell(value):
    return str(value).replace("|", "\\|")


def table(rows, platforms):
    lines = [
        "| Platform | Target | CVE | Severity | Package | Installed | Fixed |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| {} | `{}` | `{}` | {} | `{}` | `{}` | `{}` |".format(
                ", ".join(sorted(platforms[row["_key"]])),
                cell(row["target"]),
                cell(row["id"]),
                cell(row["severity"]),
                cell(row["pkg"]),
                cell(row["installed"]),
                cell(row["fixed"] or "—"),
            )
        )
    return lines


def group(rows):
    grouped = {}
    platforms = defaultdict(set)
    for row in rows:
        row = dict(row)
        row["_key"] = key(row)
        platforms[row["_key"]].add(row["_platform"])
        grouped.setdefault(row["_key"], row)
    return list(grouped.values()), platforms


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True, help="image name, e.g. scanner")
    parser.add_argument("--full", nargs="+", required=True, help="full scan reports")
    parser.add_argument("--gate", nargs="*", default=[], help="gate scan reports")
    parser.add_argument("--scanner-pin", default="", help="pinned Trivy image")
    parser.add_argument("--db-pin", default="", help="pinned Trivy DB digest")
    parser.add_argument("--summary", default=os.environ.get("GITHUB_STEP_SUMMARY", ""))
    parser.add_argument("--out", default="", help="Markdown fragment to write")
    args = parser.parse_args()

    full_rows = []
    gate_rows = []
    trivy_versions = set()

    for path in args.full:
        if not os.path.exists(path):
            print(f"missing full scan report: {path}", file=sys.stderr)
            return 2
        report = load(path)
        trivy_versions.add(((report.get("Trivy") or {}).get("Version") or "unknown"))
        p = platform(report, path)
        for row in findings(report):
            row["_platform"] = p
            full_rows.append(row)

    for path in args.gate:
        if not os.path.exists(path):
            print(f"missing gate scan report: {path}", file=sys.stderr)
            return 2
        report = load(path)
        trivy_versions.add(((report.get("Trivy") or {}).get("Version") or "unknown"))
        p = platform(report, path)
        for row in findings(report):
            row["_platform"] = p
            gate_rows.append(row)

    gate_keys = {key(row) for row in gate_rows}
    accepted_rows = [row for row in full_rows if key(row) not in gate_keys]
    accepted_grouped, accepted_platforms = group(accepted_rows)
    gate_grouped, gate_grouped_platforms = group(gate_rows)

    by_platform = defaultdict(lambda: {"full": 0, "gate": 0})
    for row in full_rows:
        by_platform[row["_platform"]]["full"] += 1
    for row in gate_rows:
        by_platform[row["_platform"]]["gate"] += 1

    lines = [f"## Release scan: `{args.name}`", ""]
    lines.append(
        "Trivy {}; scanner `{}`; DB `{}`.".format(
            ", ".join(sorted(trivy_versions)),
            args.scanner_pin or "—",
            args.db_pin or "—",
        )
    )
    lines.append("")
    lines.append("| Platform | High/critical in full scan | Blocking | Accepted |")
    lines.append("|---|---|---|---|")
    for p in sorted(by_platform):
        counts = by_platform[p]
        lines.append(
            f"| {p} | {counts['full']} | {counts['gate']} | {counts['full'] - counts['gate']} |"
        )
    lines.append("")

    if gate_grouped:
        lines.append(f"### Blocking findings ({len(gate_grouped)})")
        lines.append("")
        lines.extend(table(gate_grouped, gate_grouped_platforms))
    else:
        lines.append("**No blocking findings.**")
    lines.append("")

    if accepted_grouped:
        lines.append(
            f"<details><summary>Accepted findings for the release notes ({len(accepted_grouped)}; "
            "no fix or in the skipped bundled binaries)</summary>"
        )
        lines.append("")
        lines.extend(table(accepted_grouped, accepted_platforms))
        lines.append("</details>")
        lines.append("")
    else:
        lines.append("No accepted high or critical findings.")
        lines.append("")

    markdown = "\n".join(lines)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(markdown + "\n")
    print(markdown)

    return 1 if gate_grouped else 0


if __name__ == "__main__":
    sys.exit(main())
