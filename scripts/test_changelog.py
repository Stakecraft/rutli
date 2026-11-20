#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/changelog.py. Run: python3 scripts/test_changelog.py"""

import datetime
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import changelog as cl  # noqa: E402

CHANGELOG = """# Changelog

Intro.

## [Unreleased]

Old preamble.

### Security

- Legacy security entry.

### Changed (breaking default)

- Legacy breaking entry.

### Security

- Second legacy security block.

## [0.4.1] — 2026-11-20

### Fixed

- Old fix.

## [0.4.0] — 2026-11-14

[0.4.1]: https://github.com/Stakecraft/rutli/releases/tag/v0.4.1
[0.4.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.4.0
"""

TODAY = datetime.date(2026, 11, 20)


def make_root(files, changelog=CHANGELOG):
    d = tempfile.TemporaryDirectory()
    root = Path(d.name)
    (root / "changelog.d").mkdir()
    (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    for name, text in files.items():
        (root / "changelog.d" / name).write_text(text, encoding="utf-8")
    return d, root


class CheckTests(unittest.TestCase):
    def problems(self, name, text):
        d, root = make_root({name: text})
        with d:
            return cl.problems_in_fragment(root / "changelog.d" / name)

    def test_good(self):
        self.assertEqual(self.problems("12.fixed.md", "- **A.** B.\n"), [])
        self.assertEqual(self.problems("12.docs.md", "- One.\n- Two,\n  continued.\n"), [])

    def test_bad_names(self):
        self.assertTrue(self.problems("fixed.md", "- x\n"))
        self.assertTrue(self.problems("12.md", "- x\n"))
        self.assertTrue(self.problems("12.fixes.md", "- x\n"))
        self.assertTrue(self.problems("12.fixed.txt", "- x\n"))
        self.assertTrue(self.problems("x12.fixed.md", "- x\n"))

    def test_bad_content(self):
        self.assertTrue(self.problems("1.fixed.md", ""))
        self.assertTrue(self.problems("1.fixed.md", "\n"))
        self.assertTrue(self.problems("1.fixed.md", "- x"))  # no trailing newline
        self.assertTrue(self.problems("1.fixed.md", "- x\n\n"))
        self.assertTrue(self.problems("1.fixed.md", "text first\n"))
        self.assertTrue(self.problems("1.fixed.md", "- x\n### Heading\n"))
        self.assertTrue(self.problems("1.fixed.md", "- x \n"))
        self.assertTrue(self.problems("1.fixed.md", "- x\r\n"))
        self.assertTrue(self.problems("1.fixed.md", "- x\n```\ncode\n"))

    def test_heading_in_fence_ok(self):
        self.assertEqual(self.problems("1.fixed.md", "- x\n  ```\n  # comment\n  ```\n"), [])

    def test_check_command_ignores_readme(self):
        d, root = make_root({"README.md": "anything\n", "3.added.md": "- ok\n"})
        with d:
            self.assertEqual(cl.cmd_check(root), 0)
        d, root = make_root({"bad.md": "- ok\n"})
        with d:
            self.assertEqual(cl.cmd_check(root), 1)


class RequireTests(unittest.TestCase):
    def ev(self, diff, labels=(), pr=None, today=TODAY):
        return cl.evaluate_require(cl.parse_name_status(diff), list(labels), pr, today)

    def test_docs_only_needs_nothing(self):
        self.assertTrue(self.ev("M\tdocs/a.md\nM\tREADME.md\n")[0])

    def test_code_without_fragment_fails(self):
        for path in ("frost/a.rs", "driver/b.scala", "deploy/c.yaml", "scripts/d.sh"):
            self.assertFalse(self.ev(f"M\t{path}\n")[0], path)

    def test_fragment_passes(self):
        self.assertTrue(self.ev("M\tfrost/a.rs\nA\tchangelog.d/9.fixed.md\n")[0])

    def test_fragment_name_must_be_valid(self):
        self.assertFalse(self.ev("M\tfrost/a.rs\nA\tchangelog.d/notes.md\n")[0])
        self.assertFalse(self.ev("M\tfrost/a.rs\nA\tchangelog.d/README.md\n")[0])

    def test_deleted_fragment_does_not_count(self):
        self.assertFalse(self.ev("M\tfrost/a.rs\nD\tchangelog.d/9.fixed.md\n")[0])

    def test_label(self):
        self.assertTrue(self.ev("M\tfrost/a.rs\n", labels=["no-changelog"])[0])
        self.assertFalse(self.ev("M\tfrost/a.rs\n", labels=["other"])[0])

    def test_legacy_edit_until_date(self):
        diff = "M\tfrost/a.rs\nM\tCHANGELOG.md\n"
        self.assertTrue(self.ev(diff, today=cl.LEGACY_EDIT_UNTIL)[0])
        self.assertFalse(self.ev(diff, today=cl.LEGACY_EDIT_UNTIL + datetime.timedelta(days=1))[0])

    def test_wrong_pr_number_warns(self):
        ok, msgs = self.ev("M\tfrost/a.rs\nA\tchangelog.d/9.fixed.md\n", pr=10)
        self.assertTrue(ok)
        self.assertTrue(any(m.startswith("warning:") for m in msgs))
        ok, msgs = self.ev("M\tfrost/a.rs\nA\tchangelog.d/10.fixed.md\n", pr=10)
        self.assertFalse(any(m.startswith("warning:") for m in msgs))

    def test_rename_uses_new_path(self):
        self.assertEqual(cl.parse_name_status("R100\told.md\tchangelog.d/1.added.md\n"),
                         [("R", "changelog.d/1.added.md")])


class AssembleTests(unittest.TestCase):
    def test_merges_with_unreleased_and_orders(self):
        frags = [("fixed", "- F.\n"), ("security", "- S.\n"), ("added", "- A1.\n"), ("added", "- A2.\n"),
                 ("docs", "- D.\n")]
        out = cl.assemble_text(CHANGELOG, frags, "0.5.0", "2026-12-18")
        head, rest = out.split("## [0.5.0] — 2026-12-18\n", 1)
        self.assertIn("## [Unreleased]\n\n", head)
        self.assertNotIn("Legacy", head)  # legacy content moved under the release
        body, tail = rest.split("## [0.4.1]", 1)
        self.assertTrue(body.startswith("\nOld preamble."))
        # fragment appended to first legacy Security block, before the next heading
        self.assertLess(body.index("Legacy security entry."), body.index("- S."))
        self.assertLess(body.index("- S."), body.index("### Changed (breaking default)"))
        # new blocks in canonical order after the legacy ones
        order = [body.index(h) for h in ("### Added", "### Fixed", "### Documentation")]
        self.assertEqual(order, sorted(order))
        self.assertLess(body.index("Second legacy security block."), body.index("### Added"))
        self.assertLess(body.index("- A1."), body.index("- A2."))
        self.assertTrue(tail.startswith(" — 2026-11-20"))
        self.assertIn("[0.5.0]: https://github.com/Stakecraft/rutli/releases/tag/v0.5.0\n[0.4.1]:", out)

    def test_only_fragments_empty_unreleased(self):
        empty = CHANGELOG.replace(CHANGELOG[CHANGELOG.index("Old preamble."):CHANGELOG.index("## [0.4.1]")], "")
        out = cl.assemble_text(empty, [("fixed", "- F.\n")], "0.5.0", "2026-12-18")
        self.assertIn("## [Unreleased]\n\n## [0.5.0] — 2026-12-18\n\n### Fixed\n\n- F.\n\n## [0.4.1]", out)

    def test_nothing_to_release(self):
        empty = CHANGELOG.replace(CHANGELOG[CHANGELOG.index("Old preamble."):CHANGELOG.index("## [0.4.1]")], "")
        with self.assertRaises(ValueError):
            cl.assemble_text(empty, [], "0.5.0", "2026-12-18")

    def test_rejects_bad_input(self):
        for version, date in (("v0.5.0", "2026-12-18"), ("0.5", "2026-12-18"), ("0.5.0", "18-12-2026"),
                              ("0.5.0", "2026-13-40"), ("0.4.1", "2026-12-18")):
            with self.assertRaises(ValueError, msg=(version, date)):
                cl.assemble_text(CHANGELOG, [("fixed", "- F.\n")], version, date)

    def test_prerelease_version(self):
        out = cl.assemble_text(CHANGELOG, [("fixed", "- F.\n")], "0.5.0-rc.1", "2026-12-01")
        self.assertIn("## [0.5.0-rc.1] — 2026-12-01", out)

    def test_headings_in_code_fence_not_split(self):
        text = CHANGELOG.replace("- Legacy security entry.", "- Entry.\n\n  ```\n### not a heading\n  ```")
        out = cl.assemble_text(text, [("security", "- S.\n")], "0.5.0", "2026-12-18")
        self.assertEqual(out.count("### Security"), 2)

    def test_command_deletes_fragments_and_is_not_repeatable(self):
        d, root = make_root({"5.fixed.md": "- F.\n", "README.md": "keep\n"})
        with d:
            self.assertEqual(cl.cmd_assemble(root, "0.5.0", "2026-12-18"), 0)
            self.assertEqual(sorted(p.name for p in (root / "changelog.d").iterdir()), ["README.md"])
            self.assertIn("## [0.5.0] — 2026-12-18", (root / "CHANGELOG.md").read_text())
            self.assertEqual(cl.cmd_assemble(root, "0.5.0", "2026-12-18"), 1)

    def test_command_refuses_malformed_fragment_and_keeps_files(self):
        d, root = make_root({"5.fixed.md": "no list\n"})
        with d:
            self.assertEqual(cl.cmd_assemble(root, "0.5.0", "2026-12-18"), 1)
            self.assertEqual(CHANGELOG, (root / "CHANGELOG.md").read_text())
            self.assertTrue((root / "changelog.d" / "5.fixed.md").exists())

    def test_cli_runs(self):
        d, root = make_root({"5.fixed.md": "- F.\n"})
        with d:
            script = str(Path(cl.__file__))
            r = subprocess.run([sys.executable, script, "--root", str(root), "check"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = subprocess.run([sys.executable, script, "--root", str(root), "require", "--pr", "5",
                                "--labels", '[{"name":"x"}]'],
                               input="M\tfrost/a.rs\nA\tchangelog.d/5.fixed.md\n", capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            r = subprocess.run([sys.executable, script, "require"], input="M\tfrost/a.rs\n",
                               capture_output=True, text=True, env={**os.environ})
            self.assertEqual(r.returncode, 1)


class RepoTests(unittest.TestCase):
    def test_repository_fragments_are_well_formed(self):
        self.assertEqual(cl.cmd_check(cl.ROOT), 0)

    def test_repository_changelog_is_assemblable(self):
        text = (cl.ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        cl.assemble_text(text, [("fixed", "- F.\n")], "99.0.0", "2099-01-01")


if __name__ == "__main__":
    unittest.main()
