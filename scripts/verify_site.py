#!/usr/bin/env python3
"""Verify a production build in output/ against the advisory sources.

Run after `pelican content --settings publishconf.py`. Checks that every
advisory was generated, that the home-page numbers match the sources, and that
every URL in the build uses the canonical origin.
"""

from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ElementTree
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from validate_advisories import ADVISORY_DIR, ROOT, compute_stats, parse_advisory


CANONICAL_ORIGIN = "https://pop.byteray.co.uk"
RETIRED_HOSTS = ("pop.argus-systems.ai",)
ATOM = "{http://www.w3.org/2005/Atom}"
MAX_REPORTED_ERRORS = 40


class PageParser(HTMLParser):
    """Collect canonical links and data-stat / data-count values from one page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.canonicals: list[str] = []
        self.markers: dict[tuple[str, str], list[str]] = {}
        self._marker: tuple[str, str] | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag == "link" and "canonical" in attributes.get("rel", "").lower().split():
            self.canonicals.append(attributes.get("href", ""))
        for name in ("data-stat", "data-count"):
            if attributes.get(name):
                self._marker = (name, attributes[name])
                self._text = []

    def handle_data(self, data: str) -> None:
        if self._marker:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self._marker:
            self.markers.setdefault(self._marker, []).append("".join(self._text).strip())
            self._marker = None


def parse_page(path: Path) -> PageParser:
    parser = PageParser()
    parser.feed(path.read_text(encoding="utf-8"))
    parser.close()
    return parser


def page_url(siteurl: str, relative: str) -> str:
    return f"{siteurl}/" if relative == "index.html" else f"{siteurl}/{relative}"


def verify(output: Path, siteurl: str) -> tuple[list[str], str]:
    errors: list[str] = []

    parts = urlsplit(siteurl)
    canonical_host = urlsplit(CANONICAL_ORIGIN).netloc
    if (parts.scheme, parts.netloc, parts.path) != ("https", canonical_host, ""):
        errors.append(f"SITEURL is {siteurl!r}; production builds must use {CANONICAL_ORIGIN}")

    if not (output / "index.html").is_file():
        errors.append(f"{output} has no index.html; run the production build first")
        return errors, ""

    advisories = [parse_advisory(path) for path in sorted(ADVISORY_DIR.glob("*.md"))]
    stats = compute_stats(advisories)

    expected_slugs = {
        advisory.metadata["slug"]
        for advisory in advisories
        if advisory.status in {"published", "hidden"} and advisory.metadata.get("slug")
    }
    generated_slugs = {path.stem for path in (output / "advisory").glob("*.html")}
    for slug in sorted(expected_slugs - generated_slugs):
        errors.append(f"advisory/{slug}.html was not generated")
    for slug in sorted(generated_slugs - expected_slugs):
        errors.append(f"advisory/{slug}.html has no source advisory (stale output?)")

    expected_markers = {
        ("data-stat", "total"): str(stats.total),
        ("data-stat", "critical"): str(stats.severities["Critical"]),
        ("data-stat", "high"): str(stats.severities["High"]),
        ("data-stat", "latest-year"): stats.latest_year,
        ("data-count", "disclosed"): str(stats.disclosed),
        ("data-count", "embargoed"): str(stats.embargoed),
    }
    index_pages = sorted(output.glob("index*.html"))
    pages = sorted(output.rglob("*.html"))
    for path in pages:
        relative = path.relative_to(output).as_posix()
        page = parse_page(path)

        expected_canonical = page_url(siteurl, relative)
        if page.canonicals != [expected_canonical]:
            errors.append(
                f"{relative}: canonical links {page.canonicals}, expected [{expected_canonical!r}]"
            )

        if path not in index_pages:
            continue
        for marker, expected in expected_markers.items():
            label = f'{marker[0]}="{marker[1]}"'
            found = page.markers.get(marker, [])
            if len(found) != 1:
                errors.append(f"{relative}: expected one {label} element, found {len(found)}")
            elif found[0] != expected:
                errors.append(f"{relative}: {label} shows {found[0]!r}, expected {expected!r}")
        for marker in sorted(page.markers.keys() - expected_markers.keys()):
            errors.append(f'{relative}: unexpected {marker[0]}="{marker[1]}" element')

    feeds = sorted(output.rglob("*.xml"))
    for path in feeds:
        relative = path.relative_to(output).as_posix()
        try:
            root = ElementTree.parse(path).getroot()
        except ElementTree.ParseError as exc:
            errors.append(f"{relative}: invalid XML ({exc})")
            continue
        if root.tag != f"{ATOM}feed":
            continue
        for link in root.iter(f"{ATOM}link"):
            href = link.get("href", "")
            if not href.startswith(f"{siteurl}/"):
                errors.append(f"{relative}: link {href!r} is outside {siteurl}")
        for identifier in root.iter(f"{ATOM}id"):
            value = (identifier.text or "").strip()
            if not (value.startswith(f"{siteurl}/") or value.startswith(f"tag:{parts.netloc},")):
                errors.append(f"{relative}: id {value!r} is outside {siteurl}")

    for path in pages + feeds:
        text = path.read_text(encoding="utf-8")
        for host in RETIRED_HOSTS:
            position = text.find(host)
            if position != -1:
                line = text.count("\n", 0, position) + 1
                errors.append(f"{path.relative_to(output).as_posix()}:{line}: references {host}")

    summary = (
        f"Verified {output.relative_to(ROOT) if output.is_relative_to(ROOT) else output}: "
        f"{len(generated_slugs)} advisory pages, {len(index_pages)} index pages, "
        f"{len(pages)} HTML pages and {len(feeds)} feeds on {siteurl}.\n"
        f"Home page shows: {stats.total} advisories, {stats.severities['Critical']} critical, "
        f"{stats.severities['High']} high, latest {stats.latest_year} "
        f"({stats.disclosed} disclosed, {stats.embargoed} under embargo)."
    )
    return errors, summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "output",
        help="build directory to verify (default: output/)",
    )
    parser.add_argument(
        "--siteurl",
        default=os.environ.get("SITEURL") or CANONICAL_ORIGIN,
        help="SITEURL the site was built with (default: $SITEURL or the canonical origin)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors, summary = verify(args.output.resolve(), args.siteurl.rstrip("/"))
    if errors:
        print(f"Site verification failed with {len(errors)} problem(s):", file=sys.stderr)
        for message in errors[:MAX_REPORTED_ERRORS]:
            print(f"- {message}", file=sys.stderr)
        if len(errors) > MAX_REPORTED_ERRORS:
            print(f"- ... and {len(errors) - MAX_REPORTED_ERRORS} more", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
