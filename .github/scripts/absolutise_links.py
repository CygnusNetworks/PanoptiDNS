#!/usr/bin/env python3
"""Rewrite relative Markdown links to absolute GitHub URLs.

Docker Hub renders a repository description standalone, so every relative link
in our README (LICENSE, docs/…, Dockerfile, the badge targets) would 404 there.
This makes them absolute before the description is uploaded.

Usage: absolutise_links.py <owner/repo> <infile> <outfile>
"""

import re
import sys

# Anything already absolute, or an in-page anchor, is left alone.
ABSOLUTE = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//|#)", re.IGNORECASE)
LINK = re.compile(r"\]\((?P<target>[^)\s]+)(?P<title>\s+\"[^\"]*\")?\)")


def absolutise(markdown: str, repo: str) -> str:
    blob = f"https://github.com/{repo}/blob/main/"

    def replace(match: re.Match) -> str:
        target = match.group("target")
        if ABSOLUTE.match(target):
            return match.group(0)
        title = match.group("title") or ""
        return f"]({blob}{target.lstrip('./')}{title})"

    return LINK.sub(replace, markdown)


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    repo, infile, outfile = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(infile, encoding="utf-8") as fh:
        body = fh.read()
    header = f"> Source, issues and full documentation: https://github.com/{repo}\n\n"
    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write(header + absolutise(body, repo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
