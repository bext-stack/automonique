# SPDX-License-Identifier: Elastic-2.0

"""Read-only access to the permitted sources of the contract inventory.

Only four documents are permitted inputs, and every one of them is checked in
under `docs/product-plan/`. This module knows how to find a heading inside one,
how to read the tables and paragraphs under that heading, and how to re-find a
quotation in it. It never writes and never looks outside the four.

Whitespace is normalised before a quotation is matched, because the sources are
hard-wrapped prose: `flatten` turns a wrapped paragraph into one line so that a
quotation may span a line break without becoming unmatchable.
"""

from __future__ import annotations

import hashlib
import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# The complete permitted-input set. `AGENTS.md` permits `docs/product-plan/`
# and `plan/`; the contract for R0-01 names these four in particular.
PERMITTED_SOURCES: dict[str, str] = {
    "legacy-inventory": "docs/product-plan/reference/legacy-inventory.md",
    "feature-parity": "docs/product-plan/reference/feature-parity.md",
    "migration-plan": "docs/product-plan/reference/migration-plan.md",
    "corpus-index": "docs/product-plan/reference/corpus-index.md",
}

HEADING = re.compile(r"^(#{1,6}) .*$")
BACKTICKED = re.compile(r"`([^`]+)`")
NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
    "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
    "twenty": 20,
}


class SourceError(Exception):
    """A permitted source does not contain what the inventory cites."""


def flatten(text: str) -> str:
    """One line, single-spaced — the form quotations are matched against."""
    return " ".join(text.split())


def slugify(text: str) -> str:
    """A stable id fragment. Collisions are refused by the checker, not hidden."""
    flat = flatten(text).lower()
    flat = BACKTICKED.sub(r"\1", flat)
    slug = re.sub(r"[^a-z0-9]+", "-", flat).strip("-")
    if len(slug) <= 64:
        return slug
    cut = slug[:64]
    return cut.rsplit("-", 1)[0] if "-" in cut else cut


class Documents:
    """The permitted sources, rooted at a repository (or a copy of one).

    The root is a parameter so a test can point the whole generator at a
    temporary copy of `docs/`, change one line of it, and observe the drift
    check fail. A generator that can only ever be run against the real tree
    cannot be shown to detect anything.
    """

    def __init__(self, root: pathlib.Path | None = None) -> None:
        self.root = pathlib.Path(root) if root is not None else REPO_ROOT
        self._text: dict[str, str] = {}

    def path(self, key: str) -> pathlib.Path:
        try:
            relative = PERMITTED_SOURCES[key]
        except KeyError:
            raise SourceError(
                f"{key!r} is not a permitted source; permitted sources are "
                + ", ".join(sorted(PERMITTED_SOURCES))
            ) from None
        return self.root / relative

    def text(self, key: str) -> str:
        if key not in self._text:
            path = self.path(key)
            if not path.exists():
                raise SourceError(f"permitted source {key} is missing at {path}")
            self._text[key] = path.read_text()
        return self._text[key]

    def digest(self, key: str) -> str:
        return hashlib.sha256(self.text(key).encode()).hexdigest()

    def sections(self, key: str) -> dict[str, str]:
        """Heading line -> body, where a body includes its own subsections.

        A section runs to the next heading at the same or a higher level, so
        citing `## Phase 2 …` reaches the `### Work` list inside it. Headings
        repeat across a document (`### Work` appears under every phase), so
        `section` refuses an ambiguous one rather than silently answering with
        whichever copy happened to be last.
        """
        lines = self.text(key).splitlines()
        marks: list[tuple[int, int, str]] = []
        for number, line in enumerate(lines):
            match = HEADING.match(line)
            if match:
                marks.append((number, len(match.group(1)), line.strip()))
        found: dict[str, str] = {}
        for index, (number, level, heading) in enumerate(marks):
            end = len(lines)
            for later_number, later_level, _ in marks[index + 1:]:
                if later_level <= level:
                    end = later_number
                    break
            found.setdefault(heading, "\n".join(lines[number + 1:end]))
        return found

    def heading_occurrences(self, key: str, heading: str) -> int:
        return sum(1 for line in self.text(key).splitlines()
                   if HEADING.match(line) and line.strip() == heading)

    def section(self, key: str, heading: str) -> str:
        sections = self.sections(key)
        if heading not in sections:
            raise SourceError(
                f"{PERMITTED_SOURCES[key]} has no heading {heading!r}; "
                f"the citation names a section that is not there"
            )
        occurrences = self.heading_occurrences(key, heading)
        if occurrences > 1:
            raise SourceError(
                f"{PERMITTED_SOURCES[key]} carries {heading!r} {occurrences} times; "
                f"cite the enclosing section instead, because this one is ambiguous"
            )
        return sections[heading]

    def quotes(self, key: str, heading: str, quote: str) -> bool:
        """Does the cited section really say this?"""
        return flatten(quote) in flatten(self.section(key, heading))

    # -- structure ---------------------------------------------------------

    @staticmethod
    def tables(body: str) -> list[tuple[list[str], list[list[str]]]]:
        """(header cells, data rows) for every pipe table in a section body."""
        tables: list[tuple[list[str], list[list[str]]]] = []
        header: list[str] | None = None
        rows: list[list[str]] = []
        in_table = False
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped.startswith("|"):
                if in_table and header:
                    tables.append((header, rows))
                header, rows, in_table = None, [], False
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                in_table = True
                continue
            if header is None:
                header = cells
            else:
                rows.append(cells)
        if in_table and header:
            tables.append((header, rows))
        return tables

    @staticmethod
    def paragraphs(body: str) -> list[str]:
        """Blank-line separated paragraphs, flattened, tables excluded."""
        out, current = [], []
        for line in body.splitlines():
            if not line.strip():
                if current:
                    out.append(flatten("\n".join(current)))
                current = []
                continue
            if line.strip().startswith("|"):
                continue
            current.append(line)
        if current:
            out.append(flatten("\n".join(current)))
        return out

    def paragraph_starting(self, key: str, heading: str, prefix: str) -> str:
        for paragraph in self.paragraphs(self.section(key, heading)):
            if paragraph.startswith(prefix):
                return paragraph
        raise SourceError(
            f"{PERMITTED_SOURCES[key]} {heading!r} has no paragraph starting "
            f"{prefix!r}"
        )

    def claim(self, key: str, heading: str, pattern: str) -> int:
        """A count the source states about itself, read from the source.

        The number is never written down here: it is captured out of the
        document by `pattern`, so an inventory that disagrees with the document
        disagrees with the document rather than with a constant someone copied.
        """
        text = flatten(self.section(key, heading))
        match = re.search(pattern, text)
        if match is None:
            raise SourceError(
                f"{PERMITTED_SOURCES[key]} {heading!r} states no count matching "
                f"{pattern!r}"
            )
        total = 0
        for group in match.groups():
            token = group.strip().lower().replace(",", "")
            if token.isdigit():
                total += int(token)
            elif token in NUMBER_WORDS:
                total += NUMBER_WORDS[token]
            else:
                raise SourceError(
                    f"{PERMITTED_SOURCES[key]} {heading!r}: {group!r} is not a "
                    f"number this reader understands"
                )
        return total


def backticked(text: str) -> list[str]:
    return BACKTICKED.findall(text)
