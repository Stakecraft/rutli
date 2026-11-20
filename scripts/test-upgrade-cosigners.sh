#!/usr/bin/env bash
# Copyright 2026 StakeCraft
# SPDX-License-Identifier: Apache-2.0
# Test of scripts/upgrade-cosigners.sh against a fake kubectl (a small simulation of three
# single-replica StatefulSets and their pods). It checks the order and the safety rules the script
# promises: one pod at a time, never with another node not Ready, resumable, --only, the degraded
# path, the refusals, and --status exit codes. It does not prove anything about a real cluster: the
# cluster suite's `upgrade` scenario does (docs/cluster-suite.md).
#
#   scripts/test-upgrade-cosigners.sh        (needs python3 and jq)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

cat >"$T/kubectl" <<'PY'
#!/usr/bin/env python3
"""Fake kubectl: get sts / get pod / delete pod over a JSON state file ($FAKE_STATE)."""
import json, os, sys

path = os.environ["FAKE_STATE"]
st = json.load(open(path))
a = sys.argv[1:]
if a[:1] == ["-n"]:
    a = a[2:]

def save():
    json.dump(st, open(path, "w"))

def pod_json(p):
    return {"metadata": {"uid": p["uid"], "labels": {"controller-revision-hash": p["rev"]}},
            "status": {"conditions": [{"type": "Ready", "status": "True" if p["ready"] else "False"}]},
            "spec": {"containers": [{"name": "cosigner", "image": p["image"]}]}}

if a[:2] == ["get", "sts"]:
    items = []
    for s in st["sts"]:
        items.append({"metadata": {"name": s["name"], "generation": 1, "labels": {"rutli.io/node": str(s["id"])}},
                      "spec": {"updateStrategy": {"type": st.get("strategy", "OnDelete")},
                               "template": {"spec": {"containers": [{"name": "cosigner", "image": st["target_image"]}]}}},
                      "status": {"updateRevision": st["target_rev"], "observedGeneration": 1}})
    print(json.dumps({"items": items}))
elif a[:2] == ["get", "pod"]:
    name = a[2]
    p = st["pods"].get(name)
    if p is None:
        sys.exit(0)
    # a replacement pod becomes Ready after a few polls
    if not p["ready"] and p.get("polls_to_ready", 0) > 0:
        p["polls_to_ready"] -= 1
        if p["polls_to_ready"] == 0:
            p["ready"] = True
        save()
    print(json.dumps(pod_json(p)))
elif a[:2] == ["delete", "pod"]:
    name = a[2]
    others_ready = all(q["ready"] for n, q in st["pods"].items() if n != name)
    st["log"].append({"delete": name, "others_ready": others_ready})
    sts = next(s for s in st["sts"] if s["name"] + "-0" == name)
    st["uid"] += 1
    st["pods"][name] = {"uid": f"uid{st['uid']}", "rev": st["target_rev"], "ready": False,
                        "image": st["target_image"], "polls_to_ready": 2}
    save()
else:
    sys.exit("fake kubectl: unsupported " + " ".join(a))
PY
chmod +x "$T/kubectl"

# new_state OLD_OR_NEW_1 OLD_OR_NEW_2 OLD_OR_NEW_3 [notready-node-id...]
new_state() {
  python3 - "$T/state.json" "$@" <<'PY'
import json, sys
path, *args = sys.argv[1:]
revs = args[:3]
notready = {int(x) for x in args[3:]}
st = {"uid": 0, "target_rev": "rev-new", "target_image": "img:new", "log": [], "sts": [], "pods": {}}
for i, r in enumerate(revs, 1):
    name = f"rutli-cosigner-n{i}"
    st["sts"].append({"id": i, "name": name})
    st["uid"] += 1
    st["pods"][name + "-0"] = {"uid": f"uid{st['uid']}", "rev": "rev-new" if r == "new" else "rev-old",
                               "ready": i not in notready, "image": "img:new" if r == "new" else "img:old"}
json.dump(st, open(path, "w"))
PY
}

run() { # args...: runs the script, captures output in $T/out, exit code in $RC
  RC=0
  KUBECTL="$T/kubectl" FAKE_STATE="$T/state.json" UPGRADE_POLL_SECONDS=0 \
    "$REPO/scripts/upgrade-cosigners.sh" -n test --settle 0 "$@" >"$T/out" 2>&1 || RC=$?
}
deleted() { jq -r '[.log[].delete | sub("rutli-cosigner-n"; "") | sub("-0"; "")] | join(",")' "$T/state.json"; }
never_with_other_down() { jq -e 'all(.log[]; .others_ready)' "$T/state.json" >/dev/null; }
expect() { # description, condition(0 = ok)
  if [ "$2" -eq 0 ]; then echo "ok   $1"; else echo "FAIL $1" >&2; cat "$T/out" >&2; exit 1; fi
}
chk() { local d="$1"; shift; if "$@"; then expect "$d" 0; else expect "$d" 1; fi; }

echo "==> a full roll: nodes 1, 2, 3 in order, one at a time"
new_state old old old
run
chk "exit 0" test "$RC" -eq 0
chk "deleted 1,2,3 in order" test "$(deleted)" = "1,2,3"
chk "no pod was deleted while another was not Ready" never_with_other_down
chk "final status is clean" grep -q "upgrade complete" "$T/out"

echo "==> resume: node 1 is already on the target revision"
new_state new old old
run
chk "exit 0" test "$RC" -eq 0
chk "only 2,3 deleted" test "$(deleted)" = "2,3"

echo "==> nothing to do"
new_state new new new
run
chk "exit 0, no deletes" test "$RC" -eq 0 -a "$(deleted)" = ""

echo "==> --only 2"
new_state old old old
run --only 2
chk "exit 0" test "$RC" -eq 0
chk "only node 2 deleted" test "$(deleted)" = "2"

echo "==> a node is not Ready: refused without --allow-degraded"
new_state old old old 2
run
chk "refused" test "$RC" -ne 0
chk "nothing deleted" test "$(deleted)" = ""

echo "==> a node is not Ready: --allow-degraded rolls it first, then the rest"
new_state old old old 2
run --allow-degraded
chk "exit 0" test "$RC" -eq 0
chk "order 2,1,3" test "$(deleted)" = "2,1,3"
chk "never a second node down" never_with_other_down

echo "==> two nodes not Ready: refused even with --allow-degraded"
new_state old old old 2 3
run --allow-degraded
chk "refused" test "$RC" -ne 0
chk "nothing deleted" test "$(deleted)" = ""

echo "==> --only another node while one is broken: refused"
new_state old old old 2
run --allow-degraded --only 3
chk "refused" test "$RC" -ne 0
chk "nothing deleted" test "$(deleted)" = ""

echo "==> not OnDelete: refused"
new_state old old old
jq '.strategy = "RollingUpdate"' "$T/state.json" >"$T/s2" && mv "$T/s2" "$T/state.json"
run
chk "refused" test "$RC" -ne 0
chk "says why" grep -q "not OnDelete" "$T/out"

echo "==> --status exit codes"
new_state old new new
run --status
chk "pending roll: exit 3" test "$RC" -eq 3
chk "shows the old node" grep -q "Ready,OLD" "$T/out"
new_state new new new
run --status
chk "current: exit 0" test "$RC" -eq 0
new_state new new new 3
run --status
chk "not Ready: exit 1" test "$RC" -eq 1

echo "==> --dry-run changes nothing"
new_state old old old
run --dry-run
chk "exit 0, no deletes" test "$RC" -eq 0 -a "$(deleted)" = ""

echo "all upgrade-cosigners tests passed"
