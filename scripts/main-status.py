#!/usr/bin/env python3
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
"""Keep one issue, "main is red", in step with the checks on main.

Called by .github/workflows/main-status.yml each time one of the push-to-main workflows completes.

  * A watched workflow failed on the commit that triggered the call: open the issue, or comment on
    the open one (once per failed run).
  * Every watched workflow is green on the current tip of main: comment and close the open issue.

Needs `gh` with GH_TOKEN (actions: read, issues: write) and GITHUB_REPOSITORY. Standard library only.
Tests: scripts/test_main_status.py.
"""

import json
import os
import subprocess
import sys

# Names of the workflows (`name:` in .github/workflows/*.yml) that run unfiltered on every push to main.
# A workflow added to this list must trigger on `push: branches: [main]` without a `paths` filter.
WATCHED = [
    "CI",
    "E2E ceremonies",
    "Load test",
    "Cluster suite (kind)",
    "Image build check",
]

TITLE = "main is red"
LABELS = ("prio:p0", "type:test")
RED = {"failure", "timed_out", "startup_failure"}
GREEN = {"success", "skipped", "neutral"}


def classify(runs, watched=WATCHED):
    """runs: workflow runs (API objects) of one commit. Returns {workflow: (state, run or None)}.

    state: green | red | pending (not finished, or never started) | unknown (cancelled and the like).
    The latest run of a workflow counts (a re-run replaces the failure it repeats).
    """
    latest = {}
    for r in runs:
        if r.get("event") != "push" or r.get("name") not in watched:
            continue
        cur = latest.get(r["name"])
        if cur is None or (r["run_number"], r.get("run_attempt", 1)) > (cur["run_number"], cur.get("run_attempt", 1)):
            latest[r["name"]] = r
    out = {}
    for name in watched:
        r = latest.get(name)
        if r is None or r.get("status") != "completed":
            out[name] = ("pending", r)
        elif r.get("conclusion") in RED:
            out[name] = ("red", r)
        elif r.get("conclusion") in GREEN:
            out[name] = ("green", r)
        else:
            out[name] = ("unknown", r)
    return out


def all_green(states):
    return all(s == "green" for s, _ in states.values())


def failed(states):
    return [(n, r) for n, (s, r) in states.items() if s == "red"]


def render_failure(sha, subject, failures, repo):
    """Markdown body: the commit, the failing workflows, their failing jobs and links."""
    lines = [f"First failing commit seen: [`{sha[:12]}`](https://github.com/{repo}/commit/{sha}) {subject}", ""]
    for name, run, jobs in failures:
        lines.append(f"- **{name}**: [run {run['id']}]({run['html_url']}) ({run.get('conclusion')})")
        for j in jobs:
            lines.append(f"  - failing job: [{j['name']}]({j['html_url']}) ({j.get('conclusion')})")
    lines += ["", "Closed automatically when every check is green on the tip of main."]
    return "\n".join(lines)


def render_update(sha, subject, failures, repo):
    return render_failure(sha, subject, failures, repo).replace("First failing commit seen:", "Failing again on", 1)


class Gh:
    """Thin wrapper over the gh CLI; tests replace it."""

    def __init__(self, repo):
        self.repo = repo

    def _run(self, args, stdin=None):
        p = subprocess.run(["gh", *args], capture_output=True, text=True, input=stdin)
        if p.returncode != 0:
            raise RuntimeError(f"gh {' '.join(args[:3])} failed: {p.stderr.strip()}")
        return p.stdout

    def api(self, path):
        return json.loads(self._run(["api", path]))

    def runs_for(self, sha):
        return self.api(f"repos/{self.repo}/actions/runs?head_sha={sha}&per_page=100")["workflow_runs"]

    def jobs(self, run_id):
        return self.api(f"repos/{self.repo}/actions/runs/{run_id}/jobs?per_page=100")["jobs"]

    def tip(self):
        return self.api(f"repos/{self.repo}/commits/main")["sha"]

    def commit_subject(self, sha):
        return self.api(f"repos/{self.repo}/commits/{sha}")["commit"]["message"].split("\n", 1)[0]

    def open_issue(self):
        out = json.loads(self._run(["issue", "list", "--repo", self.repo, "--state", "open", "--label", LABELS[0],
                                    "--search", f'"{TITLE}" in:title', "--json", "number,title,body,comments"]))
        out = [i for i in out if i["title"] == TITLE]
        return out[0] if out else None

    def create_issue(self, body):
        args = ["issue", "create", "--repo", self.repo, "--title", TITLE, "--body-file", "-"]
        for label in LABELS:
            args += ["--label", label]
        self._run(args, stdin=body)

    def comment(self, number, body):
        self._run(["issue", "comment", str(number), "--repo", self.repo, "--body-file", "-"], stdin=body)

    def close(self, number):
        self._run(["issue", "close", str(number), "--repo", self.repo])


def handle(gh, event_sha, repo):
    """Returns a list of log lines. Exit status: 1 while the commit of this event is red."""
    log = []
    states = classify(gh.runs_for(event_sha))
    red = False
    fails = failed(states)
    if fails:
        red = True
        issue = gh.open_issue()
        seen = ""
        if issue:
            seen = (issue.get("body") or "") + "\n".join(c.get("body", "") for c in issue.get("comments", []))
        new = [(n, r) for n, r in fails if r["html_url"] not in seen]
        if new:
            failures = [(n, r, [j for j in gh.jobs(r["id"]) if j.get("conclusion") in RED]) for n, r in new]
            subject = gh.commit_subject(event_sha)
            if issue:
                gh.comment(issue["number"], render_update(event_sha, subject, failures, repo))
                log.append(f"commented on #{issue['number']}")
            else:
                gh.create_issue(render_failure(event_sha, subject, failures, repo))
                log.append("opened the issue")
        else:
            log.append("failure already on the issue")
    else:
        log.append("no red workflow on " + event_sha[:12])

    tip = gh.tip()
    tip_states = states if tip == event_sha else classify(gh.runs_for(tip))
    if all_green(tip_states):
        issue = gh.open_issue()
        if issue:
            links = "\n".join(f"- {n}: {r['html_url']}" for n, (_, r) in tip_states.items())
            gh.comment(issue["number"], f"Every check is green on the tip of main, `{tip[:12]}`:\n\n{links}\n\nClosing.")
            gh.close(issue["number"])
            log.append(f"closed #{issue['number']}")
    else:
        pending = [n for n, (s, _) in tip_states.items() if s != "green"]
        log.append("tip " + tip[:12] + " not fully green yet: " + ", ".join(pending))
    return red, log


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["EVENT_SHA"]
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        print("EVENT_SHA is not a commit hash", file=sys.stderr)
        return 2
    red, log = handle(Gh(repo), sha, repo)
    print("\n".join(log))
    return 1 if red else 0


if __name__ == "__main__":
    sys.exit(main())
