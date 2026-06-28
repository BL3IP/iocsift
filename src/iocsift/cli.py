"""Command-line interface for iocsift."""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import Counter
from typing import List, Optional

from . import __version__
from .enrich import enrich_ioc
from .extract import extract_iocs
from .models import IOC


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iocsift",
        description="Extract and enrich indicators of compromise (IOCs) from text/logs.",
    )
    p.add_argument("input", nargs="?", default="-", help="input file, or '-' for stdin (default)")
    p.add_argument("-f", "--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("-t", "--types", help="comma-separated IOC types to keep (e.g. ipv4,domain,sha256)")
    p.add_argument(
        "--online",
        action="store_true",
        help="enable online enrichment (reverse DNS + keyless Shodan InternetDB)",
    )
    p.add_argument("-o", "--output", help="write results to this file instead of stdout")
    p.add_argument("-V", "--version", action="version", version=f"iocsift {__version__}")
    return p


def _render(iocs: List[IOC], fmt: str) -> str:
    if fmt == "json":
        return json.dumps([i.to_dict() for i in iocs], indent=2)
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["type", "value", "enrichment"])
        for i in iocs:
            writer.writerow([i.type, i.value, json.dumps(i.enrichment)])
        return buf.getvalue().rstrip("\n")
    # table
    if not iocs:
        return "No IOCs found."
    wt = max([len(i.type) for i in iocs] + [len("TYPE")])
    wv = max([len(i.value) for i in iocs] + [len("VALUE")])
    lines = [f"{'TYPE'.ljust(wt)}  {'VALUE'.ljust(wv)}", f"{'-' * wt}  {'-' * wv}"]
    for i in iocs:
        lines.append(f"{i.type.ljust(wt)}  {i.value.ljust(wv)}")
    counts = Counter(i.type for i in iocs)
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    lines += ["", f"Total: {len(iocs)} IOCs ({summary})"]
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.input == "-":
        text = sys.stdin.read()
    else:
        with open(args.input, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()

    iocs = extract_iocs(text)
    if args.types:
        wanted = {x.strip().lower() for x in args.types.split(",")}
        iocs = [i for i in iocs if i.type in wanted]
    iocs.sort(key=lambda i: (i.type, i.value))
    for i in iocs:
        enrich_ioc(i, online=args.online)

    out = _render(iocs, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"wrote {len(iocs)} IOCs to {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
