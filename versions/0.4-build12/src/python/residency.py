"""Private opt-in and bounded recovery decisions. No ServiceManagement calls.

Only the signed Mac UI may request real OS mutations in an approved build.
This module never registers a service, approves instructions or clears pending.
"""
import argparse
import json
import math
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))  # bundled, pinned sibling in isolated CLI
import sentinel

WINDOW = 600.0
MAX_STARTS = 3
KINDS = ("helper", "owner", "watcher")
REASONS = {"OFF", "EXPLICIT_ENABLE", "EXPLICIT_RESUME", "USER_PAUSE", "USER_QUIT",
           "EXPLICIT_DISABLE", "CRASH_LOOP", "CLOCK_CHANGED", "OS_DISABLED",
           "INVALID_POLICY_PAUSED"}


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise sentinel.StateError("Invalid residency time")
    return float(value)


def _empty(root):
    return {"version": 1, "root": str(root), "desired_login": False,
            "desired_monitor": False, "reason": "OFF", "last_event_epoch": 0.0,
            "budgets": {kind: [] for kind in KINDS}}


def _load(root, state):
    value = sentinel.read_json(state / "residency.json", None)
    if value is None:
        return _empty(root)
    if (not isinstance(value, dict) or set(value) != set(_empty(root)) or
            type(value["version"]) is not int or value["version"] != 1 or
            value["root"] != str(root) or type(value["desired_login"]) is not bool or
            type(value["desired_monitor"]) is not bool or not isinstance(value["reason"], str) or
            value["reason"] not in REASONS or
            not isinstance(value["budgets"], dict) or set(value["budgets"]) != set(KINDS)):
        raise sentinel.StateError("Invalid residency policy")
    _time(value["last_event_epoch"])
    for entries in value["budgets"].values():
        if not isinstance(entries, list) or len(entries) > MAX_STARTS:
            raise sentinel.StateError("Invalid recovery budget")
        if any(_time(stamp) > _time(value["last_event_epoch"]) for stamp in entries):
            raise sentinel.StateError("Recovery time exceeds recorded clock")
        if entries != sorted(entries):
            raise sentinel.StateError("Recovery times are not ordered")
    if value["desired_monitor"] and not value["desired_login"]:
        raise sentinel.StateError("Automatic monitoring requires explicit login opt-in")
    return value


def _save(state, value):
    sentinel.save_json(state / "residency.json", value)


def status(root, state):
    with sentinel.state_lock(state):
        return _load(root, state)


def choose(root, state, action, *, human_confirmed=False, now=None):
    """Persist intent BEFORE registration or stopping; OS status is never inferred."""
    if action not in {"enable", "resume", "pause", "quit", "disable", "os-disabled"}:
        raise sentinel.StateError("Unknown residency choice")
    if action in {"enable", "resume"} and human_confirmed is not True:
        raise sentinel.StateError("Explicit confirmation required")
    with sentinel.state_lock(state):
        stamp = _time(time.time() if now is None else now)
        try:
            value = _load(root, state)
        except sentinel.StateError:
            if action not in {"disable", "pause", "quit", "os-disabled"}:
                raise
            value = _empty(root)  # stop is available even with corrupt preferences
            value["reason"] = "INVALID_POLICY_PAUSED"
        if action in {"enable", "resume"}:
            sentinel.load_baseline(state, root)  # never initialize/replace a baseline
            if action == "resume" and not value["desired_login"]:
                raise sentinel.StateError("No login opt-in to resume")
            value["desired_login"] = True
            value["desired_monitor"] = True
            value["reason"] = "EXPLICIT_ENABLE" if action == "enable" else "EXPLICIT_RESUME"
            value["budgets"] = {kind: [] for kind in KINDS}
        else:
            value["desired_monitor"] = False
            if action == "disable":
                value["desired_login"] = False
            value["reason"] = {"pause": "USER_PAUSE", "quit": "USER_QUIT",
                               "disable": "EXPLICIT_DISABLE", "os-disabled": "OS_DISABLED"}[action]
            # Explicit stop can recover from a backward clock without retaining
            # future launch timestamps. Pending/baseline/history are untouched.
            value["budgets"] = {kind: [] for kind in KINDS}
        value["last_event_epoch"] = stamp
        _save(state, value)
        return value


def admit_start(root, state, kind, *, now=None):
    """One durable budget per helper/owner/watcher, shared across process crashes."""
    if kind not in KINDS:
        raise sentinel.StateError("Unknown recovery kind")
    with sentinel.state_lock(state):
        stamp = _time(time.time() if now is None else now)
        value = _load(root, state)
        if not value["desired_login"] or not value["desired_monitor"]:
            return {"action": "NOOP", "reason": value["reason"]}
        sentinel.load_baseline(state, root)
        if stamp < value["last_event_epoch"]:
            value["desired_monitor"] = False
            value["reason"] = "CLOCK_CHANGED"
            _save(state, value)
            return {"action": "PAUSED", "reason": "CLOCK_CHANGED"}
        starts = [t for t in value["budgets"][kind] if stamp - t < WINDOW]
        if len(starts) >= MAX_STARTS:
            value["desired_monitor"] = False
            value["reason"] = "CRASH_LOOP"
            value["last_event_epoch"] = stamp
            _save(state, value)
            return {"action": "PAUSED", "reason": "CRASH_LOOP"}
        due = starts[-1] + 2 ** len(starts) if starts else stamp
        if stamp < due:
            return {"action": "WAIT", "retry_at_epoch": due}
        starts.append(stamp)
        value["budgets"][kind] = starts
        value["last_event_epoch"] = stamp
        _save(state, value)
        return {"action": "START", "kind": kind, "starts_in_window": len(starts)}


def auto_monitor_allowed(policy, os_status):
    """enabled is eligibility, not RUNNING. The watcher lease proves activity."""
    return (policy.get("desired_login") is True and policy.get("desired_monitor") is True
            and os_status == "ENABLED")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=["status", "enable", "resume", "pause", "quit",
                                      "disable", "os-disabled", "admit"])
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--state-dir", type=Path, required=True)
    p.add_argument("--kind", choices=KINDS)
    p.add_argument("--human-confirmed", action="store_true")
    a = p.parse_args()
    try:
        root = a.root.resolve(strict=True)
        state = sentinel.ensure_state_dir(a.state_dir, create=False)
        if a.action == "status":
            value = status(root, state)
        elif a.action == "admit":
            value = admit_start(root, state, a.kind)
        else:
            value = choose(root, state, a.action, human_confirmed=a.human_confirmed)
        print(json.dumps(value, sort_keys=True))
        return 0
    except (sentinel.StateError, OSError, ValueError, TypeError):
        print(json.dumps({"action": "HOLD", "reason": "RESIDENCY_STATE_UNAVAILABLE"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
