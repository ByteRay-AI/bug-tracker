#!/usr/bin/env python3
"""Validate ByteRay advisory identifiers, metadata, and disclosure boundaries."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADVISORY_DIR = ROOT / "content" / "advisories"

ADVISORY_RE = re.compile(r"BYTERAY-(\d{4})-(\d{4})\Z")
LEGACY_RE = re.compile(r"adv-(\d+)\Z")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2})?\Z")
COMMITMENT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")

WITHHELD = "[WITHHELD UNTIL DISCLOSURE]"
EMBARGO_SUMMARY = "Technical details are withheld during coordinated disclosure."
EMBARGO_NOTICE_BODY = (
    "## Disclosure Notice\n\n"
    f"{EMBARGO_SUMMARY} This page will be updated in place when disclosure is permitted."
)
EMBARGO_PROOF_BODY = (
    "\n\n## Proof of Possession\n\n"
    "The commitment above records ByteRay's possession of the private report "
    "without publishing the report or material that assists vulnerability discovery."
)

BASE_REQUIRED = {"title", "date", "slug", "advisory", "state", "summary"}
EMBARGO_REQUIRED = BASE_REQUIRED | {
    "format",
    "embargo",
    "vendor",
    "product",
    "reported",
    "disclosure",
}
EMBARGO_ALLOWED = EMBARGO_REQUIRED | {"modified", "commitment"}
EMBARGO_FORBIDDEN = {
    "severity",
    "cve",
    "cwe",
    "cvss",
    "affected",
    "fixed",
    "credit",
    "tags",
}
FULL_REQUIRED = BASE_REQUIRED | {
    "format",
    "severity",
    "vendor",
    "product",
    "reported",
    "disclosure",
    "affected",
}
FULL_HEADINGS = [
    "Executive Summary",
    "Affected Products and Versions",
    "Technical Details",
    "Reachability and Preconditions",
    "Impact",
    "Remediation and Mitigation",
    "Timeline",
    "Credits",
    "References",
]
STATES = {"Reported", "Disclosed", "Patched", "Won't Fix"}
SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


@dataclass
class Advisory:
    path: Path
    metadata: dict[str, str]
    body: str
    duplicate_keys: list[str]

    @property
    def embargoed(self) -> bool:
        return self.metadata.get("embargo", "").lower() == "true"


def parse_advisory(path: Path) -> Advisory:
    text = path.read_text(encoding="utf-8")
    header, separator, body = text.partition("\n\n")
    if not separator:
        return Advisory(path, {}, "", ["<missing metadata separator>"])

    metadata: dict[str, str] = {}
    duplicates: list[str] = []
    for line_number, line in enumerate(header.splitlines(), 1):
        if ":" not in line:
            duplicates.append(f"<invalid metadata line {line_number}>")
            continue
        key, value = line.split(":", 1)
        normalized = key.strip().lower()
        if normalized in metadata:
            duplicates.append(normalized)
        metadata[normalized] = value.strip()
    return Advisory(path, metadata, body.strip(), duplicates)


def expected_embargo_title(metadata: dict[str, str]) -> str:
    vendor = metadata.get("vendor", WITHHELD)
    product = metadata.get("product", WITHHELD)
    if vendor == WITHHELD or product == WITHHELD:
        subject = WITHHELD
    elif vendor.casefold() == product.casefold():
        subject = product
    else:
        subject = f"{vendor} {product}"
    return f"{subject} — Security Issue Under Coordinated Disclosure"


def error(errors: list[str], advisory: Advisory, message: str) -> None:
    errors.append(f"{advisory.path.relative_to(ROOT)}: {message}")


def validate_base(
    advisory: Advisory,
    errors: list[str],
    seen_ids: dict[str, Path],
    seen_slugs: dict[str, Path],
) -> None:
    metadata = advisory.metadata

    if advisory.duplicate_keys:
        error(errors, advisory, f"invalid or duplicate metadata keys: {advisory.duplicate_keys}")

    missing = sorted(BASE_REQUIRED - metadata.keys())
    if missing:
        error(errors, advisory, f"missing required metadata: {', '.join(missing)}")
        return

    date = metadata["date"]
    if not DATE_RE.fullmatch(date):
        error(errors, advisory, f"invalid Date value {date!r}")

    identifier = metadata["advisory"]
    identifier_match = ADVISORY_RE.fullmatch(identifier)
    if not identifier_match:
        error(errors, advisory, f"invalid Advisory value {identifier!r}")
    elif identifier in seen_ids:
        error(
            errors,
            advisory,
            f"duplicate Advisory value also used by {seen_ids[identifier].relative_to(ROOT)}",
        )
    else:
        seen_ids[identifier] = advisory.path

    slug = metadata["slug"]
    if slug in seen_slugs:
        error(
            errors,
            advisory,
            f"duplicate Slug also used by {seen_slugs[slug].relative_to(ROOT)}",
        )
    else:
        seen_slugs[slug] = advisory.path

    stem = advisory.path.stem
    legacy_match = LEGACY_RE.fullmatch(stem)
    if legacy_match:
        if slug != stem:
            error(errors, advisory, f"legacy Slug must remain {stem!r}")
        if identifier_match:
            expected_number = int(legacy_match.group(1))
            actual_number = int(identifier_match.group(2))
            if actual_number != expected_number:
                error(
                    errors,
                    advisory,
                    f"legacy identifier number must remain {expected_number:04d}",
                )
            if DATE_RE.fullmatch(date) and identifier_match.group(1) != date[:4]:
                error(errors, advisory, "legacy identifier year must match Date year")
    else:
        if stem != identifier:
            error(errors, advisory, "new filename stem must exactly match Advisory")
        if slug != identifier:
            error(errors, advisory, "new Slug must exactly match Advisory")

    state = metadata["state"]
    if state not in STATES:
        error(errors, advisory, f"unsupported State value {state!r}")

    severity = metadata.get("severity")
    if severity and severity.casefold() not in {item.casefold() for item in SEVERITIES}:
        error(errors, advisory, f"unsupported Severity value {severity!r}")

    embargo_value = metadata.get("embargo")
    if embargo_value is not None and embargo_value.lower() != "true":
        error(errors, advisory, "remove Embargo instead of setting a non-true value")

    status = metadata.get("status")
    if status and advisory.embargoed:
        error(errors, advisory, "Status and Embargo must not be used together")


def validate_embargo(advisory: Advisory, errors: list[str]) -> None:
    metadata = advisory.metadata

    missing = sorted(EMBARGO_REQUIRED - metadata.keys())
    if missing:
        error(errors, advisory, f"embargo is missing metadata: {', '.join(missing)}")

    unexpected = sorted(metadata.keys() - EMBARGO_ALLOWED)
    if unexpected:
        error(errors, advisory, f"embargo has non-public metadata: {', '.join(unexpected)}")

    forbidden = sorted(metadata.keys() & EMBARGO_FORBIDDEN)
    if forbidden:
        error(errors, advisory, f"embargo exposes forbidden metadata: {', '.join(forbidden)}")

    if metadata.get("format") != "1":
        error(errors, advisory, "embargo Format must be 1")
    if metadata.get("state") != "Reported":
        error(errors, advisory, "embargo State must be Reported")
    if metadata.get("title") != expected_embargo_title(metadata):
        error(errors, advisory, "embargo Title does not match the fixed safe title")
    if metadata.get("summary") != EMBARGO_SUMMARY:
        error(errors, advisory, "embargo Summary does not match the fixed safe notice")

    commitment = metadata.get("commitment")
    if commitment and not COMMITMENT_RE.fullmatch(commitment):
        error(errors, advisory, "Commitment must be sha256: plus 64 lowercase hex characters")

    expected_body = EMBARGO_NOTICE_BODY + (EMBARGO_PROOF_BODY if commitment else "")
    if advisory.body != expected_body:
        error(errors, advisory, "embargo body must match the approved safe template exactly")

    if any(character in advisory.path.read_text(encoding="utf-8") for character in "█"):
        error(errors, advisory, "length-preserving redaction characters are forbidden")


def validate_full_format(advisory: Advisory, errors: list[str]) -> None:
    metadata = advisory.metadata
    missing = sorted(FULL_REQUIRED - metadata.keys())
    if missing:
        error(errors, advisory, f"Format 1 disclosure is missing metadata: {', '.join(missing)}")

    if metadata.get("format") != "1":
        return
    if metadata.get("state") == "Reported":
        error(errors, advisory, "a non-embargo Format 1 advisory cannot remain Reported")
    if metadata.get("severity") not in SEVERITIES:
        error(errors, advisory, "Format 1 Severity must use canonical title case")
    if metadata.get("title", "").endswith("Security Issue Under Coordinated Disclosure"):
        error(errors, advisory, "replace the embargo title at full disclosure")
    if metadata.get("summary") == EMBARGO_SUMMARY:
        error(errors, advisory, "replace the embargo Summary at full disclosure")

    headings = re.findall(r"^## (.+)$", advisory.body, flags=re.MULTILINE)
    position = 0
    for required_heading in FULL_HEADINGS:
        try:
            position = headings.index(required_heading, position) + 1
        except ValueError:
            error(
                errors,
                advisory,
                f"missing or out-of-order section: {required_heading}",
            )
            break


def validate_all(advisories: list[Advisory]) -> list[str]:
    errors: list[str] = []
    seen_ids: dict[str, Path] = {}
    seen_slugs: dict[str, Path] = {}

    for advisory in advisories:
        validate_base(advisory, errors, seen_ids, seen_slugs)
        if advisory.embargoed:
            validate_embargo(advisory, errors)
        elif advisory.metadata.get("format") == "1":
            validate_full_format(advisory, errors)
    return errors


def next_identifier(advisories: list[Advisory], year: int) -> str:
    numbers = []
    for advisory in advisories:
        match = ADVISORY_RE.fullmatch(advisory.metadata.get("advisory", ""))
        if match and int(match.group(1)) == year:
            numbers.append(int(match.group(2)))
    next_number = max(numbers, default=0) + 1
    if next_number > 9999:
        raise ValueError(f"identifier space exhausted for {year}")
    return f"BYTERAY-{year}-{next_number:04d}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--next-id",
        action="store_true",
        help="print the next identifier after successful validation",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=dt.date.today().year,
        help="assignment year for --next-id (default: current year)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = sorted(ADVISORY_DIR.glob("*.md"))
    if not paths:
        print(f"No advisories found in {ADVISORY_DIR}", file=sys.stderr)
        return 1

    advisories = [parse_advisory(path) for path in paths]
    errors = validate_all(advisories)
    if errors:
        print("Advisory validation failed:", file=sys.stderr)
        for message in errors:
            print(f"- {message}", file=sys.stderr)
        return 1

    embargoed = sum(advisory.embargoed for advisory in advisories)
    print(
        f"Validated {len(advisories)} advisories: "
        f"{embargoed} embargoed, {len(advisories) - embargoed} disclosed."
    )
    if args.next_id:
        print(next_identifier(advisories, args.year))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
