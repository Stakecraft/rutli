#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/main-status.py. Run: python3 scripts/test_main_status.py"""

import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("main_status", Path(__file__).with_name("main-status.py"))
ms = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ms)

REPO = "o/r"
SHA = "a" * 40
TIP = "b" * 40


def run(name, conclusion="success", status="completed", n=1, attempt=1, event="push", id_=None, branch="main"):
    rid = id_ or (abs(hash((name, n, attempt))) % 10**6)
    return {"id": rid, "name": name, "event": event, "status": status, "conclusion": conclusion,
            "run_number": n, "run_attempt": attempt, "head_branch": branch, "html_url": f"https://x/runs/{rid}"}


def all_runs(**over):
    out = []
    for w in ms.WATCHED:
        out.append(over.get(w) or run(w))
    return out


class FakeGh:
    def __init__(self, runs, tip=SHA, issue=None):
        self.runs, self.tip_sha, self.issue = runs, tip, issue
        self.created, self.comments, self.closed = [], [], []

    def runs_for(self, sha):
        return self.runs.get(sha, []) if isinstance(self.runs, dict) else self.runs

    def jobs(self, run_id):
        return [{"name": "build", "html_url": "https://x/job/1", "conclusion": "failure"},
                {"name": "other", "html_url": "https://x/job/2", "conclusion": "success"}]

    def tip(self):
        return self.tip_sha

    def commit_subject(self, sha):
        return "feat: something"

    def open_issue(self):
        return self.issue

    def create_issue(self, body):
        self.created.append(body)
        self.issue = {"number": 7, "title": ms.TITLE, "body": body, "comments": []}

    def comment(self, n, body):
        self.comments.append((n, body))

    def close(self, n):
        self.closed.append(n)
        self.issue = None


class ClassifyTests(unittest.TestCase):
    def test_all_green(self):
        self.assertTrue(ms.all_green(ms.classify(all_runs())))

    def test_missing_workflow_is_pending(self):
        runs = all_runs()[:-1]
        st = ms.classify(runs)
        self.assertEqual(st[ms.WATCHED[-1]][0], "pending")
        self.assertFalse(ms.all_green(st))

    def test_in_progress_is_pending(self):
        st = ms.classify(all_runs(CI=run("CI", None, "in_progress")))
        self.assertEqual(st["CI"][0], "pending")

    def test_red_kinds(self):
        for c in ("failure", "timed_out", "startup_failure"):
            self.assertEqual(ms.classify(all_runs(CI=run("CI", c)))["CI"][0], "red", c)

    def test_cancelled_is_unknown_not_red(self):
        st = ms.classify(all_runs(CI=run("CI", "cancelled")))
        self.assertEqual(st["CI"][0], "unknown")
        self.assertEqual(ms.failed(st), [])
        self.assertFalse(ms.all_green(st))

    def test_rerun_replaces_failure(self):
        runs = all_runs(CI=run("CI", "failure", n=5, attempt=1)) + [run("CI", "success", n=5, attempt=2)]
        self.assertEqual(ms.classify(runs)["CI"][0], "green")

    def test_tag_runs_ignored(self):
        runs = all_runs() + [run("E2E ceremonies", "failure", n=99, branch="v0.5.0-rc.1")]
        self.assertTrue(ms.all_green(ms.classify(runs)))

    def test_other_events_and_workflows_ignored(self):
        runs = all_runs() + [run("CI", "failure", n=99, event="pull_request"), run("Unrelated", "failure", n=3)]
        self.assertTrue(ms.all_green(ms.classify(runs)))


class HandleTests(unittest.TestCase):
    def test_red_opens_one_issue_with_commit_job_and_link(self):
        gh = FakeGh(all_runs(**{"E2E ceremonies": run("E2E ceremonies", "failure", id_=42)}))
        red, log = ms.handle(gh, SHA, REPO)
        self.assertTrue(red)
        self.assertEqual(len(gh.created), 1)
        body = gh.created[0]
        for needle in (SHA[:12], "feat: something", "E2E ceremonies", "https://x/runs/42", "failing job: [build]"):
            self.assertIn(needle, body)
        self.assertNotIn("other", body)  # green jobs are not listed
        self.assertEqual(gh.closed, [])

    def test_same_failure_twice_does_not_comment_again(self):
        gh = FakeGh(all_runs(CI=run("CI", "failure", id_=42)))
        ms.handle(gh, SHA, REPO)
        ms.handle(gh, SHA, REPO)
        self.assertEqual(len(gh.created), 1)
        self.assertEqual(gh.comments, [])

    def test_second_failing_workflow_comments(self):
        gh = FakeGh(all_runs(CI=run("CI", "failure", id_=42)))
        ms.handle(gh, SHA, REPO)
        gh.runs = all_runs(CI=run("CI", "failure", id_=42), **{"Load test": run("Load test", "failure", id_=43)})
        ms.handle(gh, SHA, REPO)
        self.assertEqual(len(gh.created), 1)
        self.assertEqual(len(gh.comments), 1)
        self.assertIn("runs/43", gh.comments[0][1])
        self.assertNotIn("runs/42", gh.comments[0][1])

    def test_green_tip_closes_open_issue(self):
        issue = {"number": 7, "title": ms.TITLE, "body": "x", "comments": []}
        gh = FakeGh({SHA: all_runs(CI=run("CI", "failure", id_=42)), TIP: all_runs()}, tip=TIP, issue=issue)
        red, log = ms.handle(gh, SHA, REPO)  # an older commit finishing red: comment, and the green tip closes
        self.assertTrue(red)
        self.assertEqual(gh.closed, [7])

    def test_old_commit_red_after_green_tip_opens_nothing(self):
        gh = FakeGh({SHA: all_runs(CI=run("CI", "failure", id_=42)), TIP: all_runs()}, tip=TIP)
        ms.handle(gh, SHA, REPO)
        self.assertEqual(gh.created, [])

    def test_run_url_match_is_exact(self):
        issue = {"number": 7, "title": ms.TITLE, "body": "[run 1](https://x/runs/1234)", "comments": []}
        gh = FakeGh(all_runs(CI=run("CI", "failure", id_=123)), issue=issue)
        ms.handle(gh, SHA, REPO)
        self.assertEqual(len(gh.comments), 1)

    def test_green_without_issue_does_nothing(self):
        gh = FakeGh(all_runs())
        red, log = ms.handle(gh, SHA, REPO)
        self.assertFalse(red)
        self.assertEqual((gh.created, gh.comments, gh.closed), ([], [], []))

    def test_pending_tip_keeps_issue_open(self):
        issue = {"number": 7, "title": ms.TITLE, "body": "x", "comments": []}
        gh = FakeGh({SHA: all_runs(), TIP: all_runs()[:2]}, tip=TIP, issue=issue)
        red, log = ms.handle(gh, SHA, REPO)
        self.assertFalse(red)
        self.assertEqual(gh.closed, [])


class WorkflowTests(unittest.TestCase):
    """The watched names exist and trigger on every push to main, without a paths filter."""

    def test_watched_workflows_push_unfiltered(self):
        wf = Path(__file__).resolve().parent.parent / ".github" / "workflows"
        names = {}
        for f in wf.glob("*.yml"):
            text = f.read_text(encoding="utf-8")
            for line in text.splitlines():
                if line.startswith("name:"):
                    names[line[5:].strip().strip('"')] = (f, text)
                    break
        for w in ms.WATCHED:
            self.assertIn(w, names, f"no workflow named {w!r}")
            f, text = names[w]
            on = text.split("\njobs:", 1)[0]
            self.assertIn("push:", on, f.name)
            push = on.split("  push:", 1)[1]
            push = push.split("\n  pull_request:", 1)[0].split("\n  workflow_dispatch:", 1)[0].split("\n  schedule:", 1)[0]
            self.assertIn("branches: [main]", push, f.name)
            self.assertNotIn("paths", push, f"{f.name}: push to main must not be path-filtered")


if __name__ == "__main__":
    unittest.main()
