#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Changelog fragments.

Every pull request adds one small file under changelog.d/ instead of editing CHANGELOG.md, so
merges stop conflicting on the same lines. At release time `assemble` turns the fragments into a
release section.

    scripts/changelog.py check
    scripts/changelog.py require [--pr N] [--labels JSON] < `git diff --name-status BASE...HEAD`
    scripts/changelog.py assemble [--keep] VERSION DATE

Fragment name: `<PR number>.<section>.md`, section one of SECTIONS below. Standard library only.
"""

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# section key -> heading in CHANGELOG.md; the dict order is the order in a release. Security first, as in every
# release so far, then Keep a Changelog order, then the two repository-specific sections.
SECTIONS = {
    "security": "Security",
    "added": "Added",
    "changed": "Changed",
    "deprecated": "Deprecated",
    "removed": "Removed",
    "fixed": "Fixed",
    "build": "Build",
    "docs": "Documentation",
}

# A pull request touching these paths needs a fragment (or the label below).
CODE_PREFIXES = ("frost/", "driver/", "deploy/", "scripts/")
SKIP_LABEL = "no-changelog"

# Until this date (inclusive) a pull request that edits CHANGELOG.md directly also satisfies
# `require`: pull requests opened before the switch keep passing. After it, only fragments count.
# Remove LEGACY_EDIT_UNTIL (and the branch in `require`) with the first release on or after this date.
LEGACY_EDIT_UNTIL = datetime.date(2026, 12, 18)

FRAGMENT_RE = re.compile(r"^(\d+)\.([a-z]+)\.md$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
RELEASE_LINK_RE = re.compile(r"^\[(\d[^\]]*)\]: https://github\.com/.*/releases/tag/")


def fragments_dir(root):
    return Path(root) / "changelog.d"


def list_fragments(root):
    """Every file in changelog.d/ except README.md, sorted by (PR number, section order)."""
    d = fragments_dir(root)
    if not d.is_dir():
        return []
    order = list(SECTIONS)
    files = [p for p in d.iterdir() if p.is_file() and p.name != "README.md"]

    def key(p):
        m = FRAGMENT_RE.match(p.name)
        if m and m.group(2) in order:
            return (0, int(m.group(1)), order.index(m.group(2)), p.name)
        return (1, 0, 0, p.name)

    return sorted(files, key=key)


def problems_in_fragment(path):
    """Return a list of problems with one fragment file (empty if well-formed)."""
    out = []
    m = FRAGMENT_RE.match(path.name)
    if not m:
        return [f"{path.name}: name must be <PR number>.<section>.md"]
    if m.group(2) not in SECTIONS:
        out.append(f"{path.name}: unknown section '{m.group(2)}' (use one of {', '.join(SECTIONS)})")
    try:
        text = path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return out + [f"{path.name}: not valid UTF-8"]
    if "\r" in text:
        out.append(f"{path.name}: use LF line endings")
    if not text.strip():
        return out + [f"{path.name}: empty"]
    if not text.endswith("\n"):
        out.append(f"{path.name}: must end with a newline")
    if text.endswith("\n\n"):
        out.append(f"{path.name}: remove the blank line at the end")
    if not re.match(r"[-*] ", text):
        out.append(f"{path.name}: start with a list item ('- **What changed.** Why it matters.')")
    in_fence = False
    for n, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        elif not in_fence and re.match(r"^#{1,6}\s", line):
            out.append(f"{path.name}:{n}: no headings in a fragment; the section comes from the file name")
        if line != line.rstrip():
            out.append(f"{path.name}:{n}: trailing whitespace")
    if in_fence:
        out.append(f"{path.name}: unclosed code fence")
    return out


def cmd_check(root):
    problems = []
    for p in list_fragments(root):
        problems += problems_in_fragment(p)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if not problems:
        print(f"changelog fragments: {len(list_fragments(root))} well-formed")
    return 1 if problems else 0


def parse_name_status(text):
    """Lines of `git diff --name-status`: 'A\\tpath', 'R100\\told\\tnew'. Returns [(status, path)]."""
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0]:
            out.append((parts[0][0], parts[-1]))
            if parts[0][0] in "RC" and len(parts) >= 3:
                out.append(("D", parts[1]))  # the old path counts as touched (not as added)
    return out


def evaluate_require(changes, labels, pr_number, today):
    """Return (ok, messages). Messages starting with 'warning:' do not fail the check."""
    msgs = []
    paths = [p for _, p in changes]
    if not any(p.startswith(CODE_PREFIXES) for p in paths):
        return True, ["no change under frost/, driver/, deploy/ or scripts/: no changelog entry needed"]
    if SKIP_LABEL in labels:
        return True, [f"label '{SKIP_LABEL}' set: no changelog entry needed"]
    frags = [
        p for s, p in changes
        if s in "AR" and p.startswith("changelog.d/") and FRAGMENT_RE.match(p.split("/", 1)[1])
    ]
    if frags:
        if pr_number is not None:
            others = [f for f in frags if not f.split("/", 1)[1].startswith(f"{pr_number}.")]
            if others:
                msgs.append(
                    f"warning: fragment name does not start with this pull request's number {pr_number}: "
                    + ", ".join(others)
                )
        return True, msgs + ["a changelog fragment is present"]
    if "CHANGELOG.md" in paths and today <= LEGACY_EDIT_UNTIL:
        return True, [
            f"warning: CHANGELOG.md edited directly; accepted until {LEGACY_EDIT_UNTIL.isoformat()}, "
            "then fragments only. Prefer changelog.d/<PR>.<section>.md."
        ]
    return False, [
        "this pull request changes frost/, driver/, deploy/ or scripts/ and adds no changelog fragment.",
        "Add changelog.d/<PR number>.<section>.md (sections: " + ", ".join(SECTIONS) + "),",
        f"or put the label '{SKIP_LABEL}' on the pull request if users and operators would not notice.",
    ]


def cmd_require(args):
    labels = json.loads(args.labels) if args.labels else []
    labels = [l["name"] if isinstance(l, dict) else l for l in labels]
    changes = parse_name_status(sys.stdin.read())
    if not changes:
        print("error: no changed files on stdin (did `git diff --name-status` fail?)", file=sys.stderr)
        return 1
    ok, msgs = evaluate_require(changes, labels, args.pr, datetime.date.today())
    for m in msgs:
        if m.startswith("warning:"):
            print(f"::warning::{m[len('warning: '):]}")
        else:
            print(m, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


def split_blocks(body):
    """Split a release body into (preamble, [(heading, text)]) on '### ' headings outside fences."""
    preamble, blocks, cur = [], [], None
    in_fence = False
    for line in body.split("\n"):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        if not in_fence and line.startswith("### "):
            cur = [line[4:].strip(), []]
            blocks.append(cur)
        elif cur is None:
            preamble.append(line)
        else:
            cur[1].append(line)
    return "\n".join(preamble), [(h, "\n".join(t)) for h, t in blocks]


def assemble_text(changelog, fragments, version, date):
    """Return the new CHANGELOG.md text. `fragments` is [(section_key, text)] in release order."""
    if not VERSION_RE.match(version):
        raise ValueError(f"version '{version}' is not X.Y.Z")
    if not DATE_RE.match(date):
        raise ValueError(f"date '{date}' is not YYYY-MM-DD")
    datetime.date.fromisoformat(date)
    if re.search(rf"^## \[{re.escape(version)}\]", changelog, re.M):
        raise ValueError(f"CHANGELOG.md already has a section for {version}")
    m = re.search(r"^## \[Unreleased\][ \t]*\n", changelog, re.M)
    if not m:
        raise ValueError("CHANGELOG.md has no '## [Unreleased]' heading")
    nxt = re.search(r"^## \[", changelog[m.end():], re.M)
    end = m.end() + nxt.start() if nxt else len(changelog)
    legacy = changelog[m.end():end].strip("\n")
    if not legacy.strip() and not fragments:
        raise ValueError("nothing to release: no fragments and [Unreleased] is empty")
    pre, blocks = split_blocks(legacy)
    blocks = [[h, t.rstrip("\n")] for h, t in blocks]

    # Fragments: appended to the first legacy block of the same heading, else a new block.
    new_blocks = []
    for key in SECTIONS:
        entries = [t.strip("\n") for k, t in fragments if k == key]
        if not entries:
            continue
        text = "\n\n".join(entries)
        heading = SECTIONS[key]
        for b in blocks:
            if b[0] == heading:
                b[1] = b[1].rstrip("\n") + "\n\n" + text
                break
        else:
            new_blocks.append([heading, "\n" + text])

    parts = []
    if pre.strip():
        parts.append(pre.strip("\n"))
    for h, t in blocks + new_blocks:
        parts.append(f"### {h}\n" + (t if t.startswith("\n") else "\n" + t.lstrip("\n")))
    section = f"## [{version}] — {date}\n\n" + "\n\n".join(parts).rstrip("\n") + "\n\n"
    out = changelog[:m.end()] + "\n" + section + changelog[end:]
    link = f"[{version}]: https://github.com/Stakecraft/rutli/releases/tag/v{version}"
    if link not in out:
        lines = out.split("\n")
        for i, line in enumerate(lines):
            if RELEASE_LINK_RE.match(line):
                lines.insert(i, link)
                break
        else:
            lines = lines + ["", link, ""] if lines[-1] == "" else lines + ["", link]
        out = "\n".join(lines)
    return out


def cmd_assemble(root, version, date, keep=False):
    frags = list_fragments(root)
    problems = [p for f in frags for p in problems_in_fragment(f)]
    if problems:
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        return 1
    if "-" in version and not keep:
        print("error: a pre-release keeps the fragments for the final release: pass --keep", file=sys.stderr)
        return 1
    parts = [(FRAGMENT_RE.match(f.name).group(2), f.read_text(encoding="utf-8")) for f in frags]
    path = Path(root) / "CHANGELOG.md"
    try:
        new = assemble_text(path.read_text(encoding="utf-8"), parts, version, date)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    path.write_text(new, encoding="utf-8")
    if not keep:
        for f in frags:
            f.unlink()
    print(f"CHANGELOG.md: [{version}] — {date} written from {len(frags)} fragment(s), "
          + ("fragments kept" if keep else "fragments removed"))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(ROOT), help="repository root (default: this checkout)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="fragments are well-formed")
    rq = sub.add_parser("require", help="a change under code paths has a fragment (name-status diff on stdin)")
    rq.add_argument("--pr", type=int, help="pull request number")
    rq.add_argument("--labels", help="JSON list of label names or label objects")
    asm = sub.add_parser("assemble", help="write the release section and delete the fragments")
    asm.add_argument("--keep", action="store_true", help="keep the fragments (for a release candidate)")
    asm.add_argument("version", help="X.Y.Z or X.Y.Z-rc.N (no leading v)")
    asm.add_argument("date", help="YYYY-MM-DD")
    a = ap.parse_args(argv)
    if a.cmd == "check":
        return cmd_check(a.root)
    if a.cmd == "require":
        return cmd_require(a)
    return cmd_assemble(a.root, a.version, a.date, a.keep)


if __name__ == "__main__":
    sys.exit(main())
