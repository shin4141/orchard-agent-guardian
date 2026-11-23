#!/usr/bin/env python3
"""Orchard Sentinel PoC 01: local instruction-file change notifications.

No network, execution of observed files, or automatic approval is performed.
Polling is a testable reference and is not a pre-read enforcement boundary.
"""

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import difflib
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
from urllib.parse import urlsplit


WATCH_NAMES = frozenset(
    {"AGENTS.md", "AGENTS.override.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md"}
)
SKIP_DIRS = frozenset(
    {".git", ".venv", "node_modules", "vendor", "build", "dist", ".tox", "__pycache__"}
)
MAX_FILE_BYTES = 1024 * 1024
MAX_WATCHED_FILES = 1024
MAX_STATE_BYTES = 8 * 1024 * 1024
MAX_REVIEW_BYTES = 64 * 1024
MAX_DIFF_BYTES = 256 * 1024
MAX_REGISTRATION_FILES = 32
MAX_REGISTRATION_TEXT_BYTES = 128 * 1024
MONITOR_STALE_MIN_SECONDS = 5.0
MAX_MEANING_LINES = 512
MEANING_UNKNOWN = "変更は検知しましたが、意味を正確に説明できません"
INSTRUCTION_MEANINGS = {
    "Follow existing instructions": ("FOLLOW", "既存の指示に従うよう求めています"),
    "Ignore existing instructions": ("IGNORE", "既存の指示を無視するよう求めています"),
    "Keep a local audit log": ("LOCAL_LOG", "ローカルに監査記録を残すよう求めています"),
    "Do not send files externally": ("NO_SEND", "ファイルを外部に送らないよう求めています"),
}
SEND_HTTPS_INSTRUCTION = re.compile(
    r"(?:Send|Upload) (?:this|the) file to "
    r"https://[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?"
    r"(?:/[A-Za-z0-9._~/%-]*)?\.?")
UNINSPECTABLE_VALUES = frozenset(
    {"SYMLINK", "NONREGULAR", "OVER_LIMIT", "UNSTABLE", "TRUNCATED"}
)


class StateError(RuntimeError):
    """State cannot be trusted or decoded safely."""


class ReviewError(RuntimeError):
    """A proposed approval is unsafe or no longer matches what was reviewed."""


class NoticeBusy(StateError):
    """The watcher is updating the pending ledger."""


def _absolute(path):
    path = Path(path).expanduser()
    return path if path.is_absolute() else Path.cwd() / path


def _exists_no_follow(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def ensure_state_dir(path, create):
    """Require a private, same-user, non-symlink state directory."""
    path = _absolute(path)
    if not _exists_no_follow(path):
        if not create:
            raise StateError(f"State directory does not exist: {path}")
        path.mkdir(parents=True, mode=0o700)
    st = path.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise StateError("State directory must be a real directory, not a symlink")
    if st.st_uid != os.getuid():
        raise StateError("State directory is not owned by the current user")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(path, 0o700)
    return path


def save_json(path, value):
    """Atomically save bounded JSON with private file and directory modes."""
    path = _absolute(path)
    ensure_state_dir(path.parent, create=True)
    payload = (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    if len(payload) > MAX_STATE_BYTES:
        raise StateError("Refusing oversized state")

    fd = None
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        temp_name = None
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def read_json(path, default):
    """Read one private regular state file without following its final symlink."""
    path = _absolute(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return default
    except OSError as error:
        raise StateError(f"Cannot safely open state file {path.name}: {type(error).__name__}") from error

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise StateError(f"State file is not regular: {path.name}")
        if st.st_uid != os.getuid():
            raise StateError(f"State file is not owned by the current user: {path.name}")
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise StateError(f"State file permissions are too broad: {path.name}")
        if st.st_size > MAX_STATE_BYTES:
            raise StateError(f"State file is too large: {path.name}")
        data = bytearray()
        while len(data) <= MAX_STATE_BYTES:
            chunk = os.read(fd, min(65536, MAX_STATE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_STATE_BYTES:
            raise StateError(f"State file is too large: {path.name}")
    finally:
        os.close(fd)

    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StateError(f"Invalid JSON state in {path.name}") from error


def _stat_fingerprint(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def file_digest(path, observed_stat=None):
    """Hash one stable regular file without following a final symlink."""
    first = path.lstat()
    if stat.S_ISLNK(first.st_mode):
        return "SYMLINK"
    if not stat.S_ISREG(first.st_mode):
        return "NONREGULAR"
    if first.st_size > MAX_FILE_BYTES:
        return "OVER_LIMIT"

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            return "NONREGULAR"
        if _stat_fingerprint(opened) != _stat_fingerprint(first):
            return "UNSTABLE"
        if opened.st_size > MAX_FILE_BYTES:
            return "OVER_LIMIT"

        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                return "OVER_LIMIT"
            digest.update(chunk)
        finished = os.fstat(fd)
        if _stat_fingerprint(finished) != _stat_fingerprint(opened):
            return "UNSTABLE"
        if observed_stat is not None:
            observed_stat.append(_stat_fingerprint(finished))
        return digest.hexdigest()
    finally:
        os.close(fd)


def _uninspectable(value):
    return isinstance(value, str) and (
        value in UNINSPECTABLE_VALUES or value.startswith("UNREADABLE:")
    )


def snapshot(root, fingerprints=None):
    """Snapshot only approved names under root, bounded by depth and count."""
    found = {}
    watched_count = 0

    def record_walk_error(error):
        filename = Path(error.filename) if getattr(error, "filename", None) else root
        try:
            relative = filename.relative_to(root).as_posix() or "."
        except ValueError:
            relative = "."
        found[f"__SCAN_ERROR__/{relative}"] = "UNREADABLE:" + type(error).__name__

    for current, dirs, files in os.walk(root, followlinks=False, onerror=record_walk_error):
        current_path = Path(current)
        relative = current_path.relative_to(root)
        depth = len(relative.parts)
        if depth < 6:
            dirs[:] = sorted(
                name
                for name in dirs
                if name not in SKIP_DIRS and not (current_path / name).is_symlink()
            )
        else:
            dirs[:] = []

        for name in sorted(files):
            if name not in WATCH_NAMES:
                continue
            if watched_count >= MAX_WATCHED_FILES:
                found["__SCAN_LIMIT__"] = "TRUNCATED"
                return found
            watched_count += 1
            path = current_path / name
            key = path.relative_to(root).as_posix()
            try:
                if fingerprints is None:
                    found[key] = file_digest(path)
                else:
                    observed = []
                    found[key] = file_digest(path, observed)
                    if observed:
                        fingerprints[key] = hashlib.sha256(repr(observed[0]).encode("ascii")).hexdigest()
            except (OSError, ValueError) as error:
                found[key] = "UNREADABLE:" + type(error).__name__
    return found


def delta(baseline, current):
    changes = {}
    for name in sorted(set(baseline) | set(current)):
        before, after = baseline.get(name), current.get(name)
        if before == after:
            continue
        kind = "ADDED" if before is None else "DELETED" if after is None else "CHANGED"
        if _uninspectable(after) or name.startswith("__SCAN_"):
            kind = "UNINSPECTABLE"
        changes[name] = {"kind": kind, "before": before, "after": after}
    return changes


def _validate_file_map(value, label):
    if not isinstance(value, dict):
        raise StateError(f"{label} must be an object")
    for name, digest in value.items():
        if not isinstance(name, str) or not isinstance(digest, str):
            raise StateError(f"{label} contains an invalid path or digest")
    return value


def _validate_changes(value, label):
    if not isinstance(value, dict):
        raise StateError(f"{label} must be an object")
    for name, change in value.items():
        if not isinstance(name, str) or not isinstance(change, dict):
            raise StateError(f"{label} contains an invalid change")
        if change.get("kind") not in {"ADDED", "DELETED", "CHANGED", "UNINSPECTABLE"}:
            raise StateError(f"{label} contains an invalid change kind")
        if not all(change.get(key) is None or isinstance(change.get(key), str) for key in ("before", "after")):
            raise StateError(f"{label} contains an invalid digest")
    return value


def load_baseline(state_dir, root):
    info = read_json(state_dir / "baseline.json", None)
    if info is None:
        raise StateError("No baseline. Run 'init --confirm' from a trusted state first.")
    if not isinstance(info, dict) or info.get("root") != str(root):
        raise StateError("Baseline root mismatch; refusing another project's baseline")
    _validate_file_map(info.get("files"), "baseline files")
    review_text = info.get("review_text", {})
    if not isinstance(review_text, dict) or any(
        not isinstance(name, str) or name not in info["files"] or not isinstance(content, str)
        for name, content in review_text.items()
    ):
        raise StateError("Invalid trusted comparison text")
    return info


def _empty_pending():
    return {
        "version": 3,
        "changes": {},
        "detected_at_epoch": {},
        "last_observed_changes": {},
        "unnotified_changes": {},
        "notice_versions": {},
    }


def load_pending(state_dir):
    value = read_json(state_dir / "pending.json", None)
    if value is None:
        return _empty_pending()
    if not isinstance(value, dict):
        raise StateError("pending state must be an object")
    changes = _validate_changes(value.get("changes", {}), "pending changes")
    last_observed = value.get("last_observed_changes")
    if last_observed is None:
        # A v1 file has already produced its notification attempt. Its exact current
        # state is unknown, so use the saved evidence to avoid repeating old alerts.
        last_observed = dict(changes)
    last_observed = _validate_changes(last_observed, "last observed changes")
    unnotified = value.get("unnotified_changes")
    if unnotified is None:
        # Migrate the first v2 draft without losing evidence recorded before a crash.
        notified = _validate_changes(value.get("notified_changes", changes), "notified changes")
        unnotified = {
            name: change for name, change in changes.items() if notified.get(name) != change
        }
    unnotified = _validate_changes(unnotified, "unnotified changes")
    detected = value.get("detected_at_epoch", {})
    if not isinstance(detected, dict) or any(
        not isinstance(name, str)
        or name not in changes
        or not isinstance(epoch, (int, float))
        or isinstance(epoch, bool)
        or not math.isfinite(epoch)
        or epoch < 0
        for name, epoch in detected.items()
    ):
        raise StateError("detected timestamps must be finite epochs for pending paths")
    value["version"] = 3
    value["changes"] = changes
    value["detected_at_epoch"] = detected
    value["last_observed_changes"] = last_observed
    value["unnotified_changes"] = unnotified
    versions = value.get("notice_versions", {})
    if not isinstance(versions, dict) or any(
        not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{32}", version)
        for name, version in versions.items() if name in changes
    ):
        raise StateError("Invalid pending notice versions")
    value["notice_versions"] = {name: version for name, version in versions.items() if name in changes}
    value.pop("notified_changes", None)
    if "last_notification" in value and not isinstance(value["last_notification"], dict):
        raise StateError("last notification must be an object")
    return value


def record_changes(state_dir, changes, now_epoch=None, *, observation=None):
    state = load_pending(state_dir)
    changed = changes != state["last_observed_changes"]
    if not changed and observation is None:
        return state
    now_epoch = time.time() if now_epoch is None else now_epoch
    prior = state.copy()
    if changed:
        _update_pending_changes(state, changes, now_epoch)
    history_changed = observation is not None and _record_observations(
        state_dir, prior, state, observation, now_epoch)
    if changed or history_changed:
        save_json(state_dir / "pending.json", state)
    return state


def _update_pending_changes(state, changes, now_epoch):
    previous_observation = state["last_observed_changes"]
    state["last_observed_changes"] = dict(changes)
    pending = dict(state["changes"])
    detected = dict(state["detected_at_epoch"])
    unnotified = dict(state["unnotified_changes"])
    versions = dict(state["notice_versions"])
    for name, change in changes.items():
        if name not in pending:
            detected[name] = now_epoch
        pending[name] = change
        if previous_observation.get(name) != change:
            versions[name] = uuid.uuid4().hex
            unnotified[name] = change
    state["changes"] = pending
    state["detected_at_epoch"] = detected
    state["unnotified_changes"] = unnotified
    state["notice_versions"] = versions
    if changes:
        state.setdefault("first_seen_epoch", now_epoch)
        state["last_seen_epoch"] = now_epoch


def outstanding_changes(state):
    return dict(state["unnotified_changes"])


def mark_notified(state_dir, changes, result, now_epoch=None):
    state = load_pending(state_dir)
    unnotified = dict(state["unnotified_changes"])
    for name, reported_change in changes.items():
        if unnotified.get(name) == reported_change:
            unnotified.pop(name)
    state["unnotified_changes"] = unnotified
    state["last_notification"] = {
        **result,
        "epoch": time.time() if now_epoch is None else now_epoch,
    }
    save_json(state_dir / "pending.json", state)
    return state


def _history(state_dir):
    value = read_json(state_dir / "history.json", {"version": 1, "events": []})
    if not isinstance(value, dict) or not isinstance(value.get("events"), list):
        raise StateError("Invalid approval history")
    if any(not isinstance(event, dict) or not isinstance(event.get("id"), str)
           for event in value["events"]):
        raise StateError("Invalid approval history event")
    return value


def _append_history(state_dir, event):
    history = _history(state_dir)
    if any(old["id"] == event["id"] for old in history["events"]):
        return
    updated = {"version": 1, "events": history["events"] + [event]}
    save_json(state_dir / "history.json", updated)


def _unlink_durable(path):
    path.unlink()
    fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _recover_acceptance(state_dir):
    """Complete a committed transaction or restore all precommit evidence."""
    journal_path = state_dir / "accept-journal.json"
    journal = read_json(journal_path, None)
    if journal is None:
        return
    required = {"phase", "old_baseline", "old_pending", "new_baseline",
                "new_pending", "new_history", "event"}
    if not isinstance(journal, dict) or not required.issubset(journal):
        raise StateError("Incomplete acceptance journal; refusing state access")
    if journal["phase"] not in {"PREPARED", "COMMITTED"}:
        raise StateError("Invalid acceptance journal phase")
    if not all(isinstance(journal[key], dict) for key in required - {"phase"}):
        raise StateError("Invalid acceptance journal contents")
    if journal["phase"] == "PREPARED":
        save_json(state_dir / "baseline.json", journal["old_baseline"])
        save_json(state_dir / "pending.json", journal["old_pending"])
        interrupted = dict(journal["event"])
        interrupted["result"] = "INTERRUPTED_PRECOMMIT"
        interrupted["result_epoch"] = time.time()
        _append_history(state_dir, interrupted)
    else:
        save_json(state_dir / "baseline.json", journal["new_baseline"])
        save_json(state_dir / "pending.json", journal["new_pending"])
        save_json(state_dir / "history.json", journal["new_history"])
    _unlink_durable(journal_path)


@contextmanager
def state_lock(state_dir):
    """Serialize watcher, review, and acceptance through one private lock file."""
    ensure_state_dir(state_dir, create=True)
    path = state_dir / "state.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise StateError("Unsafe state lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
        _recover_acceptance(state_dir)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextmanager
def _notice_lock(state_dir, *, shared, wait=0):
    """Read the committed ledger, without doing acceptance recovery."""
    info = state_dir.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise StateError("Unsafe notice state directory")
    path = state_dir / "state.lock"
    flags = os.O_RDONLY if shared else os.O_RDWR | os.O_CREAT
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
    except FileNotFoundError:
        if not shared or _exists_no_follow(state_dir / "accept-journal.json"):
            raise StateError("Notice state is not committed") from None
        # Compatible older state may lack a lock until the first write.
        yield
        if _exists_no_follow(path):
            raise NoticeBusy("Notice ledger changed while opening")
        return
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise StateError("Unsafe notice lock")
        mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise NoticeBusy("Notice ledger is busy") from None
                time.sleep(min(remaining, 0.025))
        if _exists_no_follow(state_dir / "accept-journal.json"):
            raise StateError("Notice state is not committed")
        yield
    finally:
        os.close(fd)


def _notice_id(state_dir, pending, key):
    """Bind the original spelling and current revision to one ASCII selector."""
    change = pending["changes"][key]
    detected = pending["detected_at_epoch"].get(key, pending.get("first_seen_epoch", 0))
    identity = [str(state_dir), key, change["kind"], change.get("before"), change.get("after"),
                detected, pending["notice_versions"].get(key)]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _notice_key(state_dir, pending, identity):
    return next((key for key in pending["changes"] if _notice_id(state_dir, pending, key) == identity), None)


def _notice_pending(state_dir):
    if not _exists_no_follow(state_dir / "pending.json"):
        raise StateError("Pending notice ledger is missing")
    pending = load_pending(state_dir)
    if len(pending["changes"]) > MAX_WATCHED_FILES + 1:
        raise StateError("Pending notice count exceeds the limit")
    return pending


def _dismissed_notices(history):
    return {event["notice_id"] for event in history["events"]
            if event.get("result") == "NOTICE_DISMISSED_UNCONFIRMED" and isinstance(event.get("notice_id"), str)}


def notice_list_once(root, state_dir):
    with _notice_lock(state_dir, shared=True):
        load_baseline(state_dir, root)
        pending = _notice_pending(state_dir)
        closed = _dismissed_notices(_history(state_dir))
        rows = []
        for key, change in sorted(pending["changes"].items()):
            identity = _notice_id(state_dir, pending, key)
            detected = pending["detected_at_epoch"].get(key, pending.get("first_seen_epoch", 0))
            last_seen = pending.get("last_seen_epoch", detected)
            if not all(type(epoch) in (int, float) and math.isfinite(epoch) and epoch >= 0
                       for epoch in (detected, last_seen)):
                raise StateError("Invalid notice timestamps")
            rows.append({"id": identity, "path": key, "kind": change["kind"],
                         "detected_epoch": detected, "last_activity_epoch": max(detected, last_seen),
                         "dismissed": identity in closed})
        return {"result": "READY", "rows": rows}


def dismiss_notice_once(root, state_dir, notice_id):
    """Record a notice dismissal in history; leave all review evidence intact."""
    with _notice_lock(state_dir, shared=False, wait=0.5):
        load_baseline(state_dir, root)
        pending = _notice_pending(state_dir)
        key = _notice_key(state_dir, pending, notice_id)
        if key is None:
            return {"result": "NOTICE_STALE"}
        history = _history(state_dir)
        if notice_id in _dismissed_notices(history):
            return {"result": "ALREADY_DISMISSED"}
        change = pending["changes"][key]
        event = {"id": uuid.uuid4().hex, "path": key, "kind": change["kind"],
                 "before": change.get("before"), "after": change.get("after"),
                 "detected_at_epoch": pending["detected_at_epoch"].get(key),
                 "notice_id": notice_id, "result": "NOTICE_DISMISSED_UNCONFIRMED", "result_epoch": time.time()}
        save_json(state_dir / "history.json", {"version": 1, "events": history["events"] + [event]})
        return {"result": "DISMISSED_UNCONFIRMED"}


def _monitor_lock_file(state_dir):
    """Open the private single-watcher lock without following a symlink."""
    ensure_state_dir(state_dir, create=False)
    fd = os.open(state_dir / "monitor.lock",
                 os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
        os.close(fd)
        raise StateError("Unsafe monitor lock")
    return fd


@contextmanager
def monitor_lease(state_dir):
    """Only one live watcher may scan one registered state directory."""
    fd = _monitor_lock_file(state_dir)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise StateError("Another watcher already holds the monitor lease") from error
        yield
    finally:
        os.close(fd)  # closing also releases flock after an abnormal exit


@contextmanager
def watch_lease(root, state_dir, registration_file):
    if registration_file is None:
        with monitor_lease(state_dir):
            yield
        return
    # Isolated Python omits the script directory from sys.path.
    helper = Path(__file__).with_name("registration_continuity.py")
    spec = importlib.util.spec_from_file_location("orchard_registration_continuity", helper)
    continuity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(continuity)
    with ExitStack() as lease:
        try:
            lease.enter_context(continuity.registered_monitor_lease(registration_file, root, state_dir))
        except (continuity.Hold, OSError) as error:
            raise StateError("The current registration or its monitor lease could not be verified") from error
        yield


def _monitor_lease_held(state_dir):
    fd = _monitor_lock_file(state_dir)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)


def _monitor_identity(value, root):
    if not isinstance(value, dict) or value.get("version") != 1 or value.get("root") != str(root):
        return None
    pid, interval, scan, token = (value.get("pid"), value.get("interval"),
                                  value.get("last_scan_epoch"), value.get("run_token"))
    if (type(pid) is not int or pid <= 0 or type(interval) not in (int, float) or
            not math.isfinite(interval) or interval <= 0 or
            type(scan) not in (int, float) or not math.isfinite(scan) or scan < 0 or
            not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token)):
        return None
    return value


def monitor_status_once(root, state_dir, now_epoch=None):
    """A fresh scan plus a held process lock is required for RUNNING."""
    ensure_state_dir(state_dir, create=False)
    value = read_json(state_dir / "monitor.json", None)
    held = _monitor_lease_held(state_dir)
    if value is None:
        return {"state": "UNKNOWN" if held else "STOPPED",
                "reason": "LEASE_WITHOUT_HEARTBEAT" if held else "NO_WATCHER"}
    identity = _monitor_identity(value, root)
    if identity is None:
        return {"state": "UNKNOWN", "reason": "INVALID_HEARTBEAT"}
    if not held:
        return {"state": "STOPPED", "reason": "WATCHER_EXITED",
                "pid": identity["pid"], "run_token": identity["run_token"]}
    now = time.time() if now_epoch is None else now_epoch
    age = now - identity["last_scan_epoch"]
    if age < 0 or age > max(MONITOR_STALE_MIN_SECONDS, 3 * identity["interval"]):
        return {"state": "UNKNOWN", "reason": "STALE_SCAN",
                "pid": identity["pid"], "run_token": identity["run_token"]}
    return {"state": "RUNNING", "reason": "FRESH_SCAN_AND_LEASE",
            "pid": identity["pid"], "run_token": identity["run_token"],
            "last_scan_epoch": identity["last_scan_epoch"]}


def monitor_stop_once(root, state_dir, expected_token):
    """Request a graceful stop of exactly the currently responsive watcher."""
    status = monitor_status_once(root, state_dir)
    if status["state"] != "RUNNING" or status.get("run_token") != expected_token:
        return {"result": "REFUSED_STALE_OR_NOT_RUNNING"}
    with state_lock(state_dir):
        current = _monitor_identity(read_json(state_dir / "monitor.json", None), root)
        if current is None or current["run_token"] != expected_token:
            return {"result": "REFUSED_STALE_OR_NOT_RUNNING"}
        save_json(state_dir / "monitor-control.json",
                  {"version": 1, "run_token": expected_token, "request": "STOP",
                   "requested_at_epoch": time.time()})
    return {"result": "STOP_REQUESTED", "run_token": expected_token}


def registration_preview(root):
    """Show an exact, bounded human-reviewable initial snapshot before init."""
    files = snapshot(root)
    if (len(files) > MAX_REGISTRATION_FILES or
            any(name.startswith("__SCAN_") or _uninspectable(digest)
                for name, digest in files.items())):
        raise StateError("Registration preview cannot safely show every watched file")
    entries = []
    total_bytes = 0
    for name, digest in sorted(files.items()):
        content, checked_digest, _ = _review_file(root, name)
        total_bytes += len(content.encode("utf-8"))
        if checked_digest != digest or total_bytes > MAX_REGISTRATION_TEXT_BYTES:
            raise StateError("Registration preview changed or exceeds its text limit")
        entries.append({"path": name, "sha256": digest, "content": content})
    token = hashlib.sha256(json.dumps(files, sort_keys=True).encode("utf-8")).hexdigest()
    return {"root": str(root), "files": entries, "snapshot_token": token}


def _review_parts(key):
    if not isinstance(key, str) or len(key) > 1024:
        raise ReviewError("Invalid target path")
    parts = Path(key).parts
    if (not parts or len(parts) > 7 or key.startswith("/") or
            Path(*parts).as_posix() != key or parts[-1] not in WATCH_NAMES or
            any(part in (".", "..") or part in SKIP_DIRS for part in parts[:-1])):
        raise ReviewError("Target must be one watched file under the selected root")
    return parts


def _review_file(root, key):
    """Read a stable, small UTF-8 regular file from one no-follow descriptor."""
    parts = _review_parts(key)
    directory_fd = None
    fd = None
    try:
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                               getattr(os, "O_NOFOLLOW", 0))
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                              getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        first = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(first.st_mode):
            raise ReviewError("Target is not a regular file")
        if first.st_size > MAX_REVIEW_BYTES:
            raise ReviewError("Target exceeds the 64 KiB comparison cap")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(parts[-1], flags, dir_fd=directory_fd)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or _stat_fingerprint(opened) != _stat_fingerprint(first):
            raise ReviewError("Target changed while opening")
        data = bytearray()
        while len(data) <= MAX_REVIEW_BYTES:
            chunk = os.read(fd, min(65536, MAX_REVIEW_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        finished = os.fstat(fd)
        if len(data) > MAX_REVIEW_BYTES:
            raise ReviewError("Target exceeds the 64 KiB comparison cap")
        if _stat_fingerprint(finished) != _stat_fingerprint(opened):
            raise ReviewError("Target changed while reading")
        content = bytes(data).decode("utf-8")
        return content, hashlib.sha256(data).hexdigest(), list(_stat_fingerprint(finished))
    except UnicodeDecodeError as error:
        raise ReviewError("Target is not valid UTF-8") from error
    except OSError as error:
        raise ReviewError("Target is unreadable or unsafe") from error
    finally:
        if fd is not None:
            os.close(fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _instruction_meaning(raw_line):
    """Recognize entire instruction lines only; never infer from a substring."""
    line = raw_line.removesuffix("\n")
    direct = INSTRUCTION_MEANINGS.get(line.removesuffix("."))
    if direct is not None:
        return direct
    if SEND_HTTPS_INSTRUCTION.fullmatch(line):
        return ("SEND_HTTPS", "ファイルを記載されたHTTPSアドレスへ送るよう求めています")
    return None


def _quoted_line_indexes(lines):
    """Exclude common Markdown quotation regions from instruction semantics."""
    quoted = set()
    fence = None
    html_comment = False
    blockquote = False
    for index, line in enumerate(lines):
        raw = line.removesuffix("\n")
        marker = re.match(r"^\s*(`{3,}|~{3,})", raw)
        if marker:
            run = marker.group(1)
            if fence is None:
                fence = (run[0], len(run))
            elif run[0] == fence[0] and len(run) >= fence[1] and not raw[marker.end():].strip():
                fence = None
            quoted.add(index)
            continue
        if fence is not None:
            quoted.add(index)
            continue
        if html_comment or "<!--" in raw:
            quoted.add(index)
            if "<!--" in raw:
                html_comment = True
            if "-->" in raw:
                html_comment = False
            continue
        if raw.lstrip().startswith(">"):
            blockquote = True
            quoted.add(index)
        elif blockquote and raw.strip():
            quoted.add(index)
        else:
            blockquote = False
    return quoted


def explain_change_ja(old_content, content):
    """Explain only bounded, exact instruction-line patterns with line evidence."""
    old_lines = old_content.splitlines(keepends=True)
    new_lines = content.splitlines(keepends=True)
    result = {"version": 1, "status": "UNEXPLAINED", "summary_ja": MEANING_UNKNOWN,
              "scope_ja": "変更された行だけを説明します。説明できても安全性の判定ではありません。",
              "before_lines": [], "after_lines": [], "limitations_ja": []}
    if len(old_lines) > MAX_MEANING_LINES or len(new_lines) > MAX_MEANING_LINES:
        result["limitations_ja"].append("行数が説明の上限を超えました。原文と差分を確認してください。")
        return result

    old_quoted = _quoted_line_indexes(old_lines)
    new_quoted = _quoted_line_indexes(new_lines)
    summaries = []
    for tag, old_start, old_end, new_start, new_end in difflib.SequenceMatcher(
            a=old_lines, b=new_lines, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        before = []
        after = []
        for start, end, source, quoted, destination in (
                (old_start, old_end, old_lines, old_quoted, before),
                (new_start, new_end, new_lines, new_quoted, after)):
            for index in range(start, end):
                raw = source[index].removesuffix("\n")
                known = None if index in quoted else _instruction_meaning(source[index])
                destination.append({"line": index + 1, "original": raw,
                                    "rule_id": known[0] if known else None,
                                    "meaning_ja": known[1] if known else "定義済み規則では説明できません"})
        result["before_lines"].extend(before)
        result["after_lines"].extend(after)
        if any(record["rule_id"] is None for record in before + after):
            result["limitations_ja"].append("定義済みの文型に一致しない変更行があります。")
            continue
        if tag == "insert":
            if len(after) == 1 and after[0]["rule_id"] == "SEND_HTTPS":
                summaries.append("ファイルのHTTPSアドレスへの送信を求める指示が追加されました。")
            else:
                summaries.append(f"定義済みの指示が{len(after)}行追加されました。")
        elif tag == "delete":
            summaries.append(f"定義済みの指示が{len(before)}行削除されました。")
        elif len(before) == len(after) == 1 and before[0]["original"] != after[0]["original"]:
            pair = (before[0]["rule_id"], after[0]["rule_id"])
            if pair == ("FOLLOW", "IGNORE"):
                summaries.append("既存の指示に従う指示が、既存の指示を無視する指示に反転しました。")
            elif pair == ("IGNORE", "FOLLOW"):
                summaries.append("既存の指示を無視する指示が、既存の指示に従う指示に反転しました。")
            elif pair[0] != pair[1]:
                summaries.append("定義済みの指示が別の指示に置き換わりました。")
            else:
                result["limitations_ja"].append("同じ指示の書式変更は意味の変化として説明しません。")
        else:
            result["limitations_ja"].append("複数行の置き換えは指示の対応関係を確定できません。")

    if not summaries and not result["limitations_ja"]:
        result["limitations_ja"].append("説明できる指示行の変更がありません。")
    if len(summaries) > 8:
        result["limitations_ja"].append("変更箇所が多いため、短い説明にまとめません。")
    result["limitations_ja"] = list(dict.fromkeys(result["limitations_ja"]))
    if not result["limitations_ja"]:
        result["status"] = "EXPLAINED"
        result["summary_ja"] = " ".join(summaries)
    return result


IMPACT_VERSION = 1
IMPACT_EVIDENCE_LIMIT = 24
IMPACT_DESTINATION_LIMIT = 32
IMPACT_LINE_BYTES = 4096
DESTINATION_FEED_LIMIT = 8 * 1024 * 1024
DESTINATION_FEED_MAX_AGE = 24 * 60 * 60
# Populated only for an approved and independently verified offline feed artifact.
URLHAUS_OFFLINE_SHA256 = None
_HTTP_LITERAL = re.compile(r"""https?://[^\s<>"'`「」『』、。]+""", re.IGNORECASE)
_DOMAIN_LITERAL = re.compile(r"(?<![\w.@/%-])(?:[A-Za-z0-9-]{1,63}\.)+(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})(?![\w.@%-])")
_ACTION = re.compile(
    r"\b(?:(?:the )?(?:agent|assistant|ai|you)\s+(?:must|shall|should|may|is allowed to)\s+|"
    r"(?:always|automatically|first|then|please)\s+)*"
    r"(send|upload|post|transmit|forward|export|share|collect|read|retrieve|access|copy|"
    r"delete|erase|wipe|purge|remove|destroy|ignore|override|approve|grant|run|write|use|keep|follow|review|update)\b",
    re.IGNORECASE,
)
_TRANSFER = re.compile(r"\b(?:send|upload|post|transmit|forward|export|share)\b|送信|アップロード|外部に共有|転送|外部へ共有", re.IGNORECASE)
_SENSITIVE = re.compile(r"\b(?:credentials?|secrets?|api[ -]?keys?|private keys?|personal data|tokens?|passwords?)\b|\.env\b|機密|認証情報|秘密鍵|個人情報|パスワード|トークン|環境変数", re.IGNORECASE)
_DESTRUCTIVE = re.compile(r"\b(?:delete|erase|wipe|purge|remove|destroy)\b|削除|消去|破壊|初期化", re.IGNORECASE)
_EXPANSIVE = re.compile(r"\b(?:ignore|override)\b|\b(?:all|any|every)\s+(?:files?|repositories|repos|projects|directories)\b|"
                        r"\b(?:grant|elevate)\b|既存の指示を無視|すべての(?:ファイル|リポジトリ)|権限(?:を拡大|を変更|を付与)", re.IGNORECASE)
_PROCEDURE = re.compile(r"\b(?:tests?|lint|format(?:ter|ting)?|docs?|documentation|review|build|local audit log|existing instructions)\b|テスト|レビュー|書式|ビルド|既存の指示|ローカル.*ログ", re.IGNORECASE)
_DURABLE = re.compile(r"\b(?:always|permanently (?:apply|follow|enforce)|from now on|every (?:future )?(?:task|session|change|run)|"
                      r"all future (?:tasks|sessions|changes|runs)|in future (?:tasks|sessions))\b|常に|毎回|今後(?:も|すべて)|恒久|継続して", re.IGNORECASE)
_APPROVER = r"(?:[A-Za-z][A-Za-z0-9_.-]{0,31}|[一-龯々ァ-ヶー]{1,12}(?:さん|氏)?)"
_SKIP_APPROVAL = re.compile(
    rf"\b(?:without (?:(?:asking|waiting) for )?|skip |bypass )(?:(?P<en_owner>{_APPROVER})['’]s )?"
    r"(?:(?:the|user|prior|individual|explicit) +)*(?:approval|permission|confirmation)\b|"
    r"\b(?:no (?:user )?(?:approval|confirmation)|(?:approval|confirmation) (?:is )?not required)\b|"
    rf"(?:(?P<ja_owner>{_APPROVER})の\s*)?(?:個別|事前|明示の)?(?:承認|確認)"
    r"(?:を(?:待たず|待つことなく|省略|求めず|経ず|確認せず|飛ば[しす]|スキップ)|(?:は|が)?不要|なし)",
    re.IGNORECASE,
)
_APPROVAL_EXEMPTION = re.compile(r"(?:user )?(?:approval|confirmation) (?:is )?not required|"
                                 r"(?:承認|確認)(?:は|が)?不要", re.IGNORECASE)
_APPROVAL_NEGATED = re.compile(
    r"\b(?:do not|must not|shall not|should not|never|don't)\b|"
    r"しては(?:なら|いけ)|しない(?:で|こと)|禁止(?:事項|する|します|です|され)|進めない|扱わない|扱うな|みなさない",
    re.IGNORECASE,
)
_APPROVAL_CHECKED = re.compile(
    r"承認(?:を(?:得て|確認して|取得して)|が(?:確認できた|得られた|記録されている)|した|された)"
    r"(?:から|後[にで]?|ら|場合|とき|変更だけ|変更のみ|ものだけ|もののみ)|"
    r"承認済みの(?:変更|申請|項目|資料)(?:だけ|のみ|を)[、\s]*",
)
_REVIEW_CHECKED = re.compile(
    r"レビュー(?:が完了(?:した|して)|を(?:完了|実施)して|の完了(?:を確認して|が確認できた))"
    r"(?:から|後[にで]?|ら|場合|とき)",
)
_CONTRACT_SCOPE = re.compile(
    r"^(?:本契約|本合意|契約第\d+条)[^、。]{0,48}付与(?:した|された)[^、。]{0,12}権限の範囲(?:内)?で",
)
_APPROVAL_SENTENCE = re.compile(r"[。！？；;]\s*|(?<=[.!?])\s+")
_APPROVAL_QUOTE = re.compile(
    r"""`[^`\n]*`|「[^」\n]*」|『[^』\n]*』|“[^”\n]*”|"[^"\n]*"|"""
    r"(?<!\w)'(?:[^'\n]|(?<=\w)'(?=\w))*'(?!\w)|‘(?:[^’\n]|(?<=\w)’(?=\w))*’",
)
_APPROVAL_DIRECTIVE = re.compile(r"^(?:AI(?:エージェント|アシスタント)?(?:は|への[^：:]{0,18}指示[：:])|(?:作業)?指示[：:])")
_APPROVAL_REQUEST_EN = (
    r"^(?:(?:please|always|automatically) +|(?:the )?(?:agent|assistant|ai|you) +(?:must|shall|should) +)*"
)
_APPROVAL_STEP = re.compile(_APPROVAL_REQUEST_EN
                            + r"(?:proceed|apply|implement|continue|make|skip|bypass|treat|mark|record)\b",
                            re.IGNORECASE)
_APPROVAL_STEP_JA = re.compile(r"(?:ください|しなさい|せよ|(?:する|う|す)こと)$")
_AS_REQUEST_JA = (r"(?:として(?:扱(?:ってください|う(?:こと)?|いなさい|え)|記録(?:してください|する(?:こと)?))|"
                  r"と(?:みな|見な)(?:してください|す(?:こと)?|せ))$")
_FALSE_APPROVAL = re.compile(r"承認済み\s*" + _AS_REQUEST_JA + "|" + _APPROVAL_REQUEST_EN
                             + r"(?:treat|mark|record)\b.{1,140}\bas (?:already )?approved$",
                             re.IGNORECASE)
_FALSE_REVIEW = re.compile(r"レビュー(?:を|も|は)[、\s]*(?:完了(?:済み)?\s*" + _AS_REQUEST_JA
                          + r"|完了扱いに(?:してください|する(?:こと)?|しなさい|せよ)$)|"
                          + _APPROVAL_REQUEST_EN
                          + r"(?:treat|mark|record)\b.{0,100}\breview\b.{0,40}\b(?:as )?(?:already )?(?:complete|completed|done)$",
                          re.IGNORECASE)
_IRREVERSIBLE = re.compile(r"\b(?:irreversibly|permanently (?:delete|erase)|securely erase|no (?:backup|recovery)|without (?:a )?(?:backup|recovery))\b|復元不能|復元できない|復元せず|バックアップ(?:なし|不要)", re.IGNORECASE)
_NEGATIVE = re.compile(r"^(?:(?:the )?(?:agent|assistant|ai|you)\s+)?(?:(?:must|shall|should|do|will|may) not|never)\b|"
                       r"(?:送信|転送|共有|取得|削除|消去|変更)(?:しない|してはならない|を禁止|は禁止)", re.IGNORECASE)
_TARGET_INTRO = re.compile(r"(?:\b(?:to|into)\s+|(?:宛先|送信先)\s*[:：]\s*)(?:[<`'\"]*|\[[^\]\n]{1,80}\]\()$", re.IGNORECASE)
_CLAUSE_BREAK = re.compile(r"(?:[。；;]\s+|\s+(?:but|however|and then)\s+|"
                           r"\s+and\s+(?=(?:send|upload|post|transmit|delete|erase|wipe|purge|remove|collect|retrieve)\b)|、ただし)", re.IGNORECASE)
_TRANSFER_ACTIONS = {"send", "upload", "post", "transmit", "forward", "export", "share"}
_DELETE_ACTIONS = {"delete", "erase", "wipe", "purge", "remove", "destroy"}


class OfflineDestinationFeed:
    """Verify one offline list. A missing list cannot produce a negative lookup."""

    def __init__(self, status="MISSING", source="URLHAUS", retrieved=None, urls=None, hosts=None):
        self.status = status
        self.source = source
        self.retrieved = retrieved
        self.urls = urls
        self.hosts = hosts

    @classmethod
    def decode(cls, data, pin, now, source="URLHAUS"):
        if (len(data) > DESTINATION_FEED_LIMIT or not isinstance(pin, str)
                or hashlib.sha256(data).hexdigest() != pin):
            return cls("INVALID", source)
        try:
            document = json.loads(data)
            if (not isinstance(document, dict) or document.get("schema") != "orchard-destination-feed/1"
                    or document.get("provider") != source or source not in {"URLHAUS", "SYNTHETIC"}):
                raise ValueError("Unrecognized feed")
            epoch = document["retrieved_epoch"]
            valid = document["valid_until_epoch"]
            if (type(epoch) is not int or not 0 <= epoch <= 253402300799 or type(valid) is not int
                    or not epoch < valid <= epoch + DESTINATION_FEED_MAX_AGE):
                raise ValueError("Invalid feed time")
            retrieved = datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")
            fields = {}
            for label in ("exact_url_sha256", "exact_host_sha256"):
                hashes = document.get(label)
                if hashes is not None and (not isinstance(hashes, list) or len(hashes) > 100_000
                        or not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)):
                    raise ValueError("Invalid exact-match index")
                fields[label] = None if hashes is None else frozenset(hashes)
            if not any(fields.values()):
                raise ValueError("No usable indicators")
        except (KeyError, ValueError, TypeError, OverflowError, RecursionError):
            return cls("INVALID", source)
        if not math.isfinite(now) or now < epoch or now >= valid:
            return cls("STALE", source, retrieved)
        return cls("READY", source, retrieved, fields["exact_url_sha256"], fields["exact_host_sha256"])

    def lookup(self, host, url):
        checked = []
        matched = []
        if self.status == "READY":
            for scope, value, entries in (("EXACT_URL", url, self.urls), ("EXACT_HOST", host, self.hosts)):
                if value is not None and entries is not None:
                    checked.append(scope)
                    if hashlib.sha256(value.encode("utf-8")).hexdigest() in entries:
                        matched.append(scope)
        return {"status": "MATCH" if matched else "NO_MATCH" if checked else "UNVERIFIED",
                "scopes": checked, "matches": matched}

    def provenance(self):
        return {"source": self.source, "state": self.status, "retrieved_at_utc": self.retrieved}


def _offline_destination_feed():
    if URLHAUS_OFFLINE_SHA256 is None:
        return OfflineDestinationFeed()
    try:
        path = Path(__file__).resolve().with_name("destination-threats.json")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > DESTINATION_FEED_LIMIT:
                return OfflineDestinationFeed("INVALID")
            data = stream.read(DESTINATION_FEED_LIMIT + 1)
    except FileNotFoundError:
        return OfflineDestinationFeed()
    except OSError:
        return OfflineDestinationFeed("INVALID")
    return OfflineDestinationFeed.decode(data, URLHAUS_OFFLINE_SHA256, time.time())


def _destination_host(text):
    text = text.removesuffix(".")
    try:
        return ipaddress.ip_address(text).compressed
    except ValueError:
        pass
    # Keep DNS identities exact. Unsupported IDN/control characters stay unresolved.
    if not text.isascii() or len(text) > 253:
        return None
    labels = text.lower().split(".")
    if len(labels) < 2 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return None
    return ".".join(labels)


def _literal_endpoint(value):
    if "\\" in value or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return None, None
    try:
        parsed = urlsplit(value)
        host = _destination_host(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        return None, None
    if host is None or parsed.username is not None or parsed.password is not None:
        return host, None
    if not value.isascii() or any(marker in value for marker in ("${", "{{")):
        return host, None
    authority = f"[{host}]" if ":" in host else host
    if port is not None and (parsed.scheme, port) not in {("http", 80), ("https", 443)}:
        authority += f":{port}"
    url = f"{parsed.scheme}://{authority}{parsed.path or '/'}"
    return host, url + ("?" + parsed.query if parsed.query else "")


def _impact_clauses(line):
    start = 0
    for match in _CLAUSE_BREAK.finditer(line):
        yield start, match.start()
        start = match.end()
    yield start, len(line)


def _destination_operands(line, transfer):
    operands = []
    spans = []
    transfer_parts = [(start, end) for start, end in _impact_clauses(line)
                      if transfer and "EXTERNAL_TRANSFER" in _impact_actions(line[start:end], False)[0]]
    for pattern, parser in ((_HTTP_LITERAL, _literal_endpoint), (_DOMAIN_LITERAL, lambda value: (_destination_host(value), None))):
        for match in pattern.finditer(line):
            start, end = match.span()
            if any(start < last and end > first for first, last in spans):
                continue
            spans.append((start, end))
            raw = match.group().rstrip(".,;!?)]}）】")
            host, url = parser(raw)
            if host is None:
                continue
            linked = any(first <= start < last and (
                _TARGET_INTRO.search(line[first:start])
                or re.match(r"[`>）)\]]*\s*(?:に|へ|宛)", line[start + len(raw):last]))
                for first, last in transfer_parts)
            identity = ("URL", url or raw) if pattern is _HTTP_LITERAL else ("HOST", host)
            if match.group().rstrip(")]}）】") != raw:
                url = None  # Ambiguous trailing punctuation is eligible for hostname lookup only.
            operands.append((host, url, linked, identity))
    return operands


def _approval_controls(line):
    """Find requests that change who decides, or substitute a stated status for a check."""
    def literal_state(match):
        value = match[0][1:-1]
        return value if value.lower() in {"承認済み", "完了", "完了済み", "approved", "complete", "completed", "done"} else " "

    visible = _APPROVAL_QUOTE.sub(literal_state, line)
    directive = bool(_APPROVAL_DIRECTIVE.match(visible))
    rules, approvers = set(), set()
    exemption = False
    for sentence in _APPROVAL_SENTENCE.split(visible):
        for start, end in _impact_clauses(sentence):
            part = sentence[start:end].strip(" \t.!?")
            if _APPROVAL_NEGATED.search(part) or _NEGATIVE.search(part):
                continue
            directed = bool(directive or _APPROVAL_STEP_JA.search(part) or _APPROVAL_STEP.match(part) or _ACTION.match(part))
            if not _APPROVAL_CHECKED.search(part):
                exemption |= bool(_APPROVAL_EXEMPTION.fullmatch(part))
                bypass = _SKIP_APPROVAL.search(part)
                if bypass and directed and not _CONTRACT_SCOPE.match(part):
                    rules.add("APPROVAL_BYPASS")
                    owner = bypass["ja_owner"] or bypass["en_owner"]
                    if owner:
                        approvers.add(owner)
                if directed and _FALSE_APPROVAL.search(part):
                    rules.add("FALSE_APPROVAL")
            if directed and _FALSE_REVIEW.search(part) and not _REVIEW_CHECKED.search(part):
                rules.add("FALSE_REVIEW_COMPLETION")
    approver = next(iter(approvers)) if len(approvers) == 1 else None
    return rules, approver, exemption or "APPROVAL_BYPASS" in rules


def _impact_actions(line, quoted):
    line = re.sub(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)", "", unicodedata.normalize("NFC", line)).strip()
    if quoted or re.match(r"^(?:(?:example|quote|引用|例)\s*[:：]|[“\"「].*[”\"」]$)", line, re.IGNORECASE):
        return ["QUOTED"], False, False, False, None
    if not line or line.strip("#*_-= ") == "":
        return ["TEXT_ONLY"], False, False, False, None
    if any(unicodedata.category(ch) in {"Cf", "Cc"} and ch != "\t" for ch in line):
        return ["UNKNOWN"], False, False, False, None
    control_rules, approver, bypass = _approval_controls(line)
    categories = set(control_rules)
    for start, end in _impact_clauses(line):
        part = line[start:end].strip()
        command = re.sub(r"^(?:(?:for|on|in|before|after|when|if)\b[^,]{1,100},\s*)", "", part, flags=re.IGNORECASE)
        match = _ACTION.match(command)
        japanese = bool(re.search(r"(?:すること|する[。.]?$|せよ|してください|しなさい|すべき|が必要|を求め|常に|毎回)", part))
        if _NEGATIVE.search(command):
            categories.add("RESTRICTION")
        elif match or japanese:
            action = match[1].lower() if match else None
            if action in _TRANSFER_ACTIONS or japanese and _TRANSFER.search(part):
                categories.add("EXTERNAL_TRANSFER")
            if _SENSITIVE.search(part) and (action in {"collect", "read", "retrieve", "access", "copy", "export", "send", "upload"}
                    or re.search(r"取得|収集|読み取|アクセス|記録|送信", part)):
                categories.add("SENSITIVE_DATA")
            if action in _DELETE_ACTIONS or japanese and _DESTRUCTIVE.search(part):
                categories.add("DESTRUCTIVE")
            if _EXPANSIVE.search(part):
                categories.add("SCOPE_CHANGE")
            if not control_rules and _PROCEDURE.search(part) and action not in {"ignore", "override", "approve", "grant"}:
                categories.add("PROCEDURE")
    if not categories and line.startswith("#") and not (_TRANSFER.search(line) or _DESTRUCTIVE.search(line) or _SENSITIVE.search(line)):
        categories.add("TEXT_ONLY")
    return sorted(categories) or ["UNKNOWN"], bool(_DURABLE.search(line)), bypass, bool(_IRREVERSIBLE.search(line)), approver


_IMPACT_LEVELS = {"QUOTED": 1, "TEXT_ONLY": 1, "PROCEDURE": 2, "RESTRICTION": 2, "SCOPE_CHANGE": 3,
                  "EXTERNAL_TRANSFER": 4, "SENSITIVE_DATA": 4, "DESTRUCTIVE": 4,
                  "APPROVAL_BYPASS": 4, "FALSE_APPROVAL": 4, "FALSE_REVIEW_COMPLETION": 4}


def _impact_line(text, index, quoted, context):
    actions, durable, bypass, irreversible, approver = _impact_actions(text, quoted)
    level = max((_IMPACT_LEVELS.get(action, 0) for action in actions), default=0)
    if level == 4:
        # Adjacent prose joins the directive only when it explicitly refers to this rule.
        durable |= bool(_DURABLE.search(context))
        bypass |= _approval_controls(context)[2]
        irreversible |= bool(_IRREVERSIBLE.search(context))
        if durable and (bypass or irreversible):
            level = 5
    return {"line": index + 1, "original": text, "actions": actions, "level": level or None,
            "persistent": durable, "skips_approval": bypass, "irreversible": irreversible,
            **({"approval_owner": approver} if approver is not None else {})}


def _impact_document(content):
    lines = content.split("\n")
    visible = [re.sub(r"<!--.*?-->", "", line) for line in lines]
    quoted = _quoted_line_indexes(visible)
    records = []
    endpoints = []
    for index, line in enumerate(lines):
        extra = []
        for following in range(index + 1, min(index + 3, len(lines))):
            text = lines[following].strip()
            if following in quoted or not re.match(r"^(?:this (?:rule|instruction|requirement)\b|"
                    r"(?:user )?(?:approval|confirmation) (?:is )?not required\b|(?:この|本)(?:指示|規則)|承認(?:は|が)?不要)", text, re.IGNORECASE):
                break
            extra.append(text)
        line_for_analysis = visible[index]
        oversized = len(line_for_analysis.encode("utf-8")) > IMPACT_LINE_BYTES
        if oversized:
            line_for_analysis = line_for_analysis.encode("utf-8")[:IMPACT_LINE_BYTES].decode("utf-8", errors="ignore")
        evidence = _impact_line(line_for_analysis, index, index in quoted, " ".join(extra))
        if oversized and "UNKNOWN" not in evidence["actions"]:
            evidence["actions"].append("UNKNOWN")
        evidence["original"] = line
        records.append(evidence)
        endpoints.append(_destination_operands(unicodedata.normalize("NFC", line_for_analysis),
                                              "EXTERNAL_TRANSFER" in evidence["actions"]))
    return records, endpoints


def explain_instruction_impact(old, new, kind, feed=None):
    """Describe observed text changes only. This output grants no action authority."""
    if feed is None:
        feed = _offline_destination_feed()
    result = {"version": IMPACT_VERSION, "kind": kind, "coverage": "UNVERIFIED", "scope": "UNKNOWN",
              "level": None, "future_use": "UNKNOWN", "evidence": [], "destinations": [], "unknown_lines": 0,
              "limits": [], "intelligence": feed.provenance(), "intent": "NOT_AVAILABLE"}
    if old is None or new is None:
        return result
    if any(len(content.encode("utf-8")) > MAX_REVIEW_BYTES or content.count("\n") >= MAX_MEANING_LINES
           for content in (old, new)):
        result["limits"].append("ANALYSIS_LIMIT")
        return result
    older, old_endpoints = _impact_document(old)
    newer, new_endpoints = _impact_document(new)
    def semantic(row):
        return (unicodedata.normalize("NFC", row["original"]).rstrip(), tuple(row["actions"]), row["level"])
    changes = difflib.SequenceMatcher(a=[semantic(row) for row in older], b=[semantic(row) for row in newer], autojunk=False)
    old_targets = {key for line in old_endpoints for _, _, linked, key in line if linked}
    old_actions = {action for row in older for action in row["actions"]}
    old_levels = {action: max(row["level"] or 0 for row in older if action in row["actions"]) for action in old_actions}
    qualifier_fields = ("persistent", "skips_approval", "irreversible")
    old_qualifiers = {action: {field for field in qualifier_fields
                              if any(row[field] for row in older if action in row["actions"])} for action in old_actions}
    result_rows = []
    destination_rows = []
    changed_endpoints = False
    for op, start_a, end_a, start_b, end_b in changes.get_opcodes():
        if op == "equal":
            # A Unicode/whitespace-only change still supplies its original line evidence.
            for a, b in zip(older[start_a:end_a], newer[start_b:end_b]):
                if a["original"] != b["original"]:
                    for row, side in ((a, "BEFORE"), (b, "AFTER")):
                        result_rows.append({"line": row["line"], "original": row["original"], "side": side,
                                            "actions": ["TEXT_ONLY"], "level": 1, "persistent": False,
                                            "skips_approval": False, "irreversible": False})
            continue
        result_rows.extend({**row, "side": "BEFORE"} for row in older[start_a:end_a])
        result_rows.extend({**row, "side": "AFTER"} for row in newer[start_b:end_b])
        replaced = sorted({host for line in old_endpoints[start_a:end_a] for host, _, linked, _ in line if linked})
        for offset in range(start_b, end_b):
            endpoints = new_endpoints[offset]
            for host, url, linked, key in endpoints:
                relation = "UNLINKED" if not linked else "UNCHANGED" if key in old_targets else "CHANGED" if replaced else "ADDED"
                changed_endpoints |= relation in {"CHANGED", "ADDED"}
                destination_rows.append({"line": offset + 1, "host": host, "relation": relation,
                                         "previous_hosts": replaced if relation == "CHANGED" else [],
                                         "lookup": feed.lookup(host, url)})
            if "EXTERNAL_TRANSFER" in newer[offset]["actions"] and not any(item[2] for item in endpoints):
                destination_rows.append({"line": offset + 1, "host": None, "relation": "DYNAMIC",
                                         "previous_hosts": [], "lookup": feed.lookup(None, None)})
    after = [row for row in result_rows if row["side"] == "AFTER"]
    unknown = sum("UNKNOWN" in row["actions"] for row in after)
    recognized = max((row["level"] or 0 for row in after), default=0)
    if kind == "DELETED":
        recognized = 2
    elif not after:
        recognized = 2 if any((row["level"] or 0) > 1 for row in result_rows) else 1
    expanded = changed_endpoints or any((row["level"] or 0) >= 3 and any(
        (row["level"] or 0) > old_levels.get(action, 0) or any(
            row[field] and field not in old_qualifiers.get(action, ()) for field in qualifier_fields)
        for action in row["actions"] if _IMPACT_LEVELS.get(action, 0) >= 3) for row in after)
    uncertain = unknown or any((row["level"] or 0) >= 3 for row in after)
    result.update(coverage="PARTIAL" if unknown else "DESCRIBED",
                  level=recognized if recognized and (not unknown or recognized >= 3) else None,
                  scope="EXPANDED" if expanded else "UNKNOWN" if uncertain else "NO_EXPANSION",
                  future_use="POSSIBLE" if any((row["level"] or 0) >= 2 for row in after)
                  else "UNKNOWN" if unknown else "NO_NEW_DIRECTIVE",
                  unknown_lines=unknown)
    result_rows.sort(key=lambda row: (row["side"] != "AFTER", -(row["level"] or 0), row["line"]))
    destination_rows.sort(key=lambda row: (row["lookup"]["status"] != "MATCH", row["relation"] == "UNLINKED", row["line"]))
    if len(result_rows) > IMPACT_EVIDENCE_LIMIT:
        result["limits"].append("EVIDENCE_LIMIT")
    if len(destination_rows) > IMPACT_DESTINATION_LIMIT:
        result["limits"].append("DESTINATION_LIMIT")
    result["evidence"] = result_rows[:IMPACT_EVIDENCE_LIMIT]
    result["destinations"] = destination_rows[:IMPACT_DESTINATION_LIMIT]
    return result


def _trusted_review_text(baseline, key, digest):
    if digest is None:
        return ""
    content = baseline.get("review_text", {}).get(key)
    if not isinstance(content, str):
        raise ReviewError("Trusted old content was not saved; a safe diff is unavailable")
    if hashlib.sha256(content.encode("utf-8")).hexdigest() != digest:
        raise ReviewError("Saved old content disagrees with the trusted hash")
    return content


def _review_diff(old_content, content):
    lines = difflib.unified_diff(
        old_content.splitlines(keepends=True), content.splitlines(keepends=True),
        fromfile="信頼済みの内容", tofile="現在の内容", lineterm="\n",
    )
    return "".join(line if line.endswith("\n") else line + " ⟵ 改行なし\n" for line in lines)


def pending_review_archive(root, state_dir, byte_limit):
    """Capture review evidence while the caller holds the old state and monitor locks."""
    pending = load_pending(state_dir)
    if not pending["changes"]:
        return []
    baseline = load_baseline(state_dir, root)
    current = snapshot(root)
    if any(name.startswith("__SCAN_") for name in current):
        raise ReviewError("The old project cannot be scanned completely")
    reviews = []
    for key, change in sorted(pending["changes"].items()):
        _review_parts(key)
        before, after = change["before"], change["after"]
        kind = change["kind"]
        if (kind not in {"ADDED", "CHANGED", "DELETED"} or before == after
                or (kind == "ADDED") != (before is None)
                or (kind == "DELETED") != (after is None)
                or baseline["files"].get(key) != before or current.get(key) != after):
            raise ReviewError("Current target no longer matches pending evidence")
        old_content = _trusted_review_text(baseline, key, before)
        content = ""
        if after is not None:
            content, digest, _ = _review_file(root, key)
            if digest != after:
                raise ReviewError("Current content changed during review")
        diff = _review_diff(old_content, content)
        if len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
            raise ReviewError("Diff cannot be compared safely within the PoC limit")
        review = {"path": key, "kind": kind, "before_SHA256": before, "after_SHA256": after,
                  "detected_at_epoch": pending["detected_at_epoch"].get(key),
                  "old_content": old_content, "content": content, "diff": diff}
        byte_limit -= len(json.dumps(review, ensure_ascii=False).encode("utf-8"))
        if byte_limit < 0:
            raise ReviewError("Pending review evidence exceeds the state limit")
        reviews.append(review)
    return reviews


def _review_unlocked(root, state_dir, key):
    baseline = load_baseline(state_dir, root)
    pending = load_pending(state_dir)
    change = pending["changes"].get(key)
    if not isinstance(change, dict):
        raise ReviewError("No approvable pending change for target")
    kind = change["kind"]
    if kind == "DELETED":
        raise ReviewError("Deleted target has no current text for approval")
    if kind == "UNINSPECTABLE":
        raise ReviewError("Pending evidence has no readable target")
    _review_parts(key)
    before, after = change.get("before"), change.get("after")
    if not isinstance(after, str) or not re.fullmatch("[0-9a-f]{64}", after):
        raise ReviewError("Baseline and pending state disagree")
    files = baseline["files"]
    if kind == "ADDED":
        # With a complete trusted baseline, a watched path missing from it
        # supplies the absence evidence. A case/normalization alias can be the
        # same path on macOS, so it cannot establish that this is a new file.
        normalized = unicodedata.normalize("NFC", key).casefold()
        version = baseline.get("version")
        if (type(version) is not int or version not in (1, 2, 3)
                or "before" not in change or before is not None or any(
                name.startswith("__SCAN_") or not re.fullmatch("[0-9a-f]{64}", digest)
                or unicodedata.normalize("NFC", name).casefold() == normalized
                for name, digest in files.items())):
            raise ReviewError("Saved baseline cannot establish absence before addition")
        if pending["last_observed_changes"].get(key) != change:
            raise ReviewError("Addition no longer matches the last observation")
    elif not isinstance(before, str) or not re.fullmatch("[0-9a-f]{64}", before) or files.get(key) != before:
        raise ReviewError("Baseline and pending state disagree")
    current = snapshot(root)
    if any(name.startswith("__SCAN_") for name in current):
        raise ReviewError("Current instruction scan is incomplete")
    if current.get(key) != after:
        raise ReviewError("Current target no longer matches pending evidence")
    content, digest, fingerprint = _review_file(root, key)
    if digest != after:
        raise ReviewError("Current content changed during review")
    old_content = _trusted_review_text(baseline, key, before)
    diff = _review_diff(old_content, content)
    if (kind != "ADDED" and not diff) or len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
        raise ReviewError("Diff cannot be compared safely within the PoC limit")
    detected = pending["detected_at_epoch"].get(key)
    identity = {"root": str(root), "path": key, "kind": kind,
                "before": before, "after": after, "detected_at_epoch": detected,
                "fingerprint": fingerprint}
    token = hashlib.sha256(json.dumps(identity, sort_keys=True).encode("utf-8")).hexdigest()
    return {**identity, "content": content, "old_content": old_content,
            "diff": diff, "meaning_ja": explain_change_ja(old_content, content),
            "review_token": token}


def review_once(root, state_dir, key, notice_id=None):
    if notice_id is not None:
        with _notice_lock(state_dir, shared=True, wait=0.5):
            baseline = load_baseline(state_dir, root)
            pending = _notice_pending(state_dir)
            key = _notice_key(state_dir, pending, notice_id)
            if key is None:
                return None
            change = pending["changes"][key]
            try:
                reviewed = _review_unlocked(root, state_dir, key)
            except ReviewError as error:
                reviewed = {"result": "REFUSED", "reason": str(error), "kind": change["kind"]}
                if change["kind"] == "DELETED":
                    deletion = _notice_deleted_diff(root, baseline, key, change.get("before"))
                    if deletion is not None:
                        reviewed.update(deletion)
        reviewed["notice_id"] = notice_id
        reviewed["impact_review"] = explain_instruction_impact(
            reviewed.get("old_content"), reviewed.get("content"), change["kind"])
        return reviewed
    with state_lock(state_dir):
        return _review_unlocked(root, state_dir, key)


def _notice_deleted_diff(root, baseline, key, before):
    """Display verified removed text while keeping deletion outside approval."""
    if not isinstance(before, str) or baseline["files"].get(key) != before:
        return None
    try:
        _review_parts(key)
        old = _trusted_review_text(baseline, key, before)
    except ReviewError:
        return None
    current = snapshot(root)
    alias = unicodedata.normalize("NFC", key).casefold()
    if any(name.startswith("__SCAN_") or unicodedata.normalize("NFC", name).casefold() == alias for name in current):
        return None
    diff = _review_diff(old, "")
    if len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
        return None
    return {"before": before, "after": None, "old_content": old, "content": "", "diff": diff}


def _refusal(state_dir, key, before, after, result, actual=None):
    event = {"id": uuid.uuid4().hex, "path": key, "before": before, "after": after,
             "actual_after": actual, "result": result, "result_epoch": time.time()}
    _append_history(state_dir, event)
    return {"result": result, "path": key}


def accept_once(root, state_dir, key, review_token, reviewed_before, reviewed_after, notice_id=None):
    """Commit one explicitly reviewed file; never called by polling or notification."""
    lock = state_lock(state_dir) if notice_id is None else _notice_lock(state_dir, shared=False, wait=0.5)
    with lock:
        if notice_id is not None:
            load_baseline(state_dir, root)
            key = _notice_key(state_dir, _notice_pending(state_dir), notice_id)
            if key is None:
                return {"result": "NOTICE_STALE"}
        try:
            review = _review_unlocked(root, state_dir, key)
        except ReviewError as error:
            return {**_refusal(state_dir, key, reviewed_before, reviewed_after,
                               "REFUSED_CHANGED_OR_UNSAFE"), "reason": str(error)}
        if (review["review_token"] != review_token or
                review["before"] != reviewed_before or review["after"] != reviewed_after):
            return _refusal(state_dir, key, reviewed_before, reviewed_after,
                            "REFUSED_CHANGED_AFTER_REVIEW", review["after"])

        old_baseline = load_baseline(state_dir, root)
        old_pending = load_pending(state_dir)
        new_baseline = dict(old_baseline)
        new_baseline["files"] = dict(old_baseline["files"])
        new_baseline["files"][key] = reviewed_after
        new_baseline["review_text"] = dict(old_baseline.get("review_text", {}))
        new_baseline["review_text"][key] = review["content"]
        new_baseline["asof_epoch"] = time.time()
        new_pending = dict(old_pending)
        for field in ("changes", "detected_at_epoch", "last_observed_changes", "unnotified_changes", "notice_versions"):
            new_pending[field] = dict(old_pending[field])
            new_pending[field].pop(key, None)

        event = {"id": uuid.uuid4().hex, "path": key, "kind": review["kind"],
                 "before": reviewed_before, "after": reviewed_after,
                 "detected_at_epoch": review["detected_at_epoch"],
                 "notice_id": _notice_id(state_dir, old_pending, key),
                 "reviewed_fingerprint": review["fingerprint"],
                 "result": "ACCEPTED", "result_epoch": time.time()}
        history = _history(state_dir)
        new_history = {"version": 1, "events": history["events"] + [event]}
        journal = {"phase": "PREPARED", "old_baseline": old_baseline,
                   "old_pending": old_pending, "new_baseline": new_baseline,
                   "new_pending": new_pending, "new_history": new_history, "event": event}
        journal_path = state_dir / "accept-journal.json"
        save_json(journal_path, journal)  # no authority changes before durable prepare
        save_json(state_dir / "baseline.json", new_baseline)
        try:
            _, final_digest, final_fingerprint = _review_file(root, key)
            unchanged = final_digest == reviewed_after and final_fingerprint == review["fingerprint"]
        except ReviewError:
            unchanged = False
        if not unchanged:
            save_json(state_dir / "baseline.json", old_baseline)
            save_json(state_dir / "pending.json", old_pending)
            result = _refusal(state_dir, key, reviewed_before, reviewed_after,
                              "REFUSED_CHANGED_DURING_ACCEPT")
            _unlink_durable(journal_path)
            return result
        journal["phase"] = "COMMITTED"
        save_json(journal_path, journal)
        save_json(state_dir / "pending.json", new_pending)
        save_json(state_dir / "history.json", new_history)
        _unlink_durable(journal_path)
        return {"result": "ACCEPTED", "path": key, "before": reviewed_before,
                "after": reviewed_after, "result_epoch": event["result_epoch"]}


def claim_alert_once(root, state_dir, key, expected_after, expected_detected, notice_id=None):
    """Persist at-most-once presentation for one unconfirmed event, without approval."""
    lock = state_lock(state_dir) if notice_id is None else _notice_lock(state_dir, shared=False)
    with lock:
        load_baseline(state_dir, root)
        pending = load_pending(state_dir) if notice_id is None else _notice_pending(state_dir)
        if notice_id is not None:
            key = _notice_key(state_dir, pending, notice_id)
            if key is None:
                return {"claimed": False, "reason": "STALE"}
            if notice_id in _dismissed_notices(_history(state_dir)):
                return {"claimed": False, "reason": "DISMISSED"}
        change = pending["changes"].get(key)
        detected = pending["detected_at_epoch"].get(key, pending.get("first_seen_epoch", 0))
        if not isinstance(change, dict) or (notice_id is None and
                (change.get("after") != expected_after or detected != expected_detected)):
            return {"claimed": False, "reason": "STALE"}
        path = state_dir / "ui-alerts.json"
        value = read_json(path, {"version": 1, "claims": {}})
        if not isinstance(value, dict) or not isinstance(value.get("claims"), dict):
            raise StateError("Invalid alert presentation state")
        old = value["claims"].get(key)
        if isinstance(old, dict) and old.get("detected_at_epoch") == detected:
            if (notice_id is None or old.get("notice_id") == notice_id
                    or ("notice_id" not in old and old.get("after") == change.get("after")
                        and key not in pending["notice_versions"])):
                return {"claimed": False, "reason": "ALREADY_SHOWN"}
        claims = dict(value["claims"])
        claims[key] = {"detected_at_epoch": detected, "after": change.get("after"),
                       "claimed_at_epoch": time.time()}
        if notice_id is not None:
            claims[key]["notice_id"] = notice_id
        save_json(path, {"version": 1, "claims": claims})
        return {"claimed": True, "path": key, "detected_at_epoch": detected}


MAX_MD_RECORDS = 2048
MAX_MD_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MD_INDEX_BYTES = 512 * 1024
MD_HISTORY_PAGE = 24
MAX_MD_TARGET_DEPTH = 32
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


def _is_digest(value):
    return isinstance(value, str) and _HEX_DIGEST.fullmatch(value) is not None


def _observation_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise StateError("Observation data cannot be verified") from error


def _observation_scope(root, state_dir):
    return hashlib.sha256(_observation_bytes([str(root), str(state_dir)])).hexdigest()


def _empty_md_index(root, state_dir, *, legacy):
    return {"version": 1, "scope": _observation_scope(root, state_dir), "records": [],
            "last": {}, "initialized": False, "legacy": legacy, "storage": None,
            "scan_issue": None, "latest_change": None, "gap_count": 0,
            "has_complete_snapshot": False}


def _md_index(pending, root, state_dir):
    index = pending.get("md_observations")
    if index is None:
        return _empty_md_index(root, state_dir, legacy=True)
    expected = {"version", "scope", "records", "last", "initialized", "legacy", "storage", "scan_issue",
                "latest_change", "gap_count", "has_complete_snapshot"}
    if (not isinstance(index, dict) or not expected.issubset(index) or index.get("version") != 1
            or index.get("scope") != _observation_scope(root, state_dir)):
        raise StateError("Observation index scope cannot be verified")
    records, last = index.get("records"), index.get("last")
    if (not isinstance(records, list) or len(records) > MAX_MD_RECORDS
            or not all(map(_is_digest, records)) or len(set(records)) != len(records)
            or not isinstance(last, dict) or len(_observation_bytes(index)) > MAX_MD_INDEX_BYTES
            or any(type(index.get(name)) is not bool for name in ("initialized", "legacy", "has_complete_snapshot"))
            or index.get("storage") not in (None, "CAPACITY", "WRITE_UNVERIFIED")
            or (index["scan_issue"] is not None and type(index["scan_issue"]) is not bool)
            or type(index.get("gap_count")) is not int or not 0 <= index["gap_count"] <= len(records)):
        raise StateError("Observation index cannot be verified")
    available = set(records)
    for entry in last.values():
        if (not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
                or entry.get("record") is not None and (not _is_digest(entry["record"]) or entry["record"] not in available)
                or entry.get("sha256") is not None and not _is_digest(entry["sha256"])
                or entry.get("stat") is not None and not _is_digest(entry["stat"])
                or entry.get("anchor") not in ("BASELINE", "OBSERVED", "LEGACY")):
            raise StateError("Observation anchor cannot be verified")
    return index


def _observation_directory(state_dir, *, create=False):
    directory = state_dir / "md-observations"
    if create and not _exists_no_follow(directory):
        directory.mkdir(mode=0o700)
        fd = os.open(state_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise StateError("Observation evidence directory is unsafe")
    return directory


def _read_md_record(state_dir, identity, scope):
    if not _is_digest(identity):
        raise StateError("Invalid observation identity")
    path = _observation_directory(state_dir) / (identity + ".json")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise StateError("Observation evidence file is unsafe")
    value = read_json(path, None)
    if (not isinstance(value, dict) or value.get("scope") != scope
            or hashlib.sha256(_observation_bytes(value)).hexdigest() != identity):
        raise StateError("Observation evidence digest differs")
    return value


class _ObservationCapacity(StateError):
    pass


class _ObservationWriter:
    """Publish immutable evidence first. The pending ledger commits its visible index."""

    def __init__(self, state_dir, index):
        self.state_dir = state_dir
        self.index = index
        self.directory = None
        self.bytes = 0
        self.count = 0

    def append(self, payload):
        if len(self.index["records"]) >= MAX_MD_RECORDS:
            raise _ObservationCapacity("Observation count cap")
        if self.directory is None:
            self.directory = _observation_directory(self.state_dir, create=True)
            for path in self.directory.iterdir():
                self.count += 1
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise StateError("Unsafe observation archive member")
                self.bytes += info.st_size
                if self.count > MAX_MD_RECORDS or self.bytes > MAX_MD_ARCHIVE_BYTES:
                    raise _ObservationCapacity("Observation archive cap")
        body = {**payload, "version": 1, "scope": self.index["scope"], "sequence": len(self.index["records"]) + 1}
        identity = hashlib.sha256(_observation_bytes(body)).hexdigest()
        path = self.directory / (identity + ".json")
        if _exists_no_follow(path):
            if _read_md_record(self.state_dir, identity, self.index["scope"]) != body:
                raise StateError("Observation evidence could not be read back")
        else:
            size = len((json.dumps(body, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
            if self.count >= MAX_MD_RECORDS or self.bytes + size > MAX_MD_ARCHIVE_BYTES:
                raise _ObservationCapacity("Observation archive cap")
            save_json(path, body)
            self.count += 1
            self.bytes += size
        self.index["records"].append(identity)
        if body["kind"] == "GAP":
            self.index["gap_count"] += 1
        else:
            self.index["latest_change"] = {"sequence": body["sequence"], "kind": body["kind"]}
        return identity


def _watch_groups(items):
    groups = {}
    for key, value in items.items():
        if not key.startswith("__SCAN_"):
            groups.setdefault(unicodedata.normalize("NFC", key), []).append((key, value))
    return groups


def _text_record(digest, text, known=True):
    return {"known": known, "sha256": digest, "text": text}


def _baseline_text(baseline, group):
    if not group:
        return _text_record(None, "")
    if len(group) != 1 or not _is_digest(group[0][1]):
        return _text_record(None, None, False)
    key, digest = group[0]
    try:
        text = _trusted_review_text(baseline, key, digest)
    except ReviewError:
        text = None
    return _text_record(digest, text)


def _observed_text(root, key, digest):
    if digest is None:
        return _text_record(None, "")
    try:
        text, actual, _ = _review_file(root, key)
        return _text_record(digest, text if actual == digest else None)
    except ReviewError:
        return _text_record(digest, None)


def _preceding_text(state_dir, index, entry, base):
    if entry.get("record") is not None:
        try:
            record = _read_md_record(state_dir, entry["record"], index["scope"])
            observed = record["current"]
            if observed["sha256"] == entry["sha256"]:
                return observed
        except (OSError, StateError, KeyError, TypeError):
            pass
    if entry["sha256"] is None:
        return _text_record(None, "")
    return base if base["known"] and entry["sha256"] == base["sha256"] else _text_record(entry["sha256"], None)


def _change_kind(before, after):
    return "ADDED" if before is None else "DELETED" if after is None else "CHANGED"


def _observation_comparison(before, after):
    if not before["known"] or not after["known"] or before["text"] is None or after["text"] is None:
        return {"status": "UNVERIFIED", "diff": None, "impact": None}
    if before["sha256"] == after["sha256"]:
        return {"status": "EQUAL", "diff": "", "impact": None}
    diff = _review_diff(before["text"], after["text"])
    if len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
        return {"status": "UNVERIFIED", "diff": None, "impact": None}
    impact = explain_instruction_impact(before["text"], after["text"], _change_kind(before["sha256"], after["sha256"]))
    return {"status": "READY", "diff": diff, "impact": impact}


def _seed_observation_index(index, prior, baseline_groups):
    for key, group in baseline_groups.items():
        if len(group) == 1 and _is_digest(group[0][1]):
            path, digest = group[0]
            index["last"][key] = {"path": path, "sha256": digest, "stat": None, "record": None, "anchor": "BASELINE"}
    if index["legacy"]:
        for key, group in _watch_groups(prior["last_observed_changes"]).items():
            if len(group) != 1:
                continue
            path, change = group[0]
            digest = change.get("after")
            if _is_digest(digest) or change["kind"] == "DELETED" and digest is None:
                index["last"][key] = {"path": path, "sha256": digest, "stat": None, "record": None, "anchor": "LEGACY"}


def _retain_legacy_pending(writer, prior, root, baseline, baseline_groups, current, epoch, capture):
    for key, change in sorted(prior["changes"].items()):
        if key.startswith("__SCAN_"):
            continue
        digest = change.get("after")
        captured = _text_record(digest if _is_digest(digest) else None, None, _is_digest(digest))
        if _is_digest(digest) and current.get(key) == digest:
            captured = _observed_text(root, key, digest)
        anchor = _baseline_text(baseline, baseline_groups.get(unicodedata.normalize("NFC", key)))
        if anchor["sha256"] != change.get("before"):
            anchor = _text_record(None, None, False)
        comparison = _observation_comparison(anchor, captured)
        identity = writer.append({"kind": "LEGACY_PENDING", "change_kind": change["kind"], "path": key,
                         "observed_epoch": prior["detected_at_epoch"].get(key), "captured_epoch": epoch, "capture": capture,
                         "notice_id": _notice_id(writer.state_dir, prior, key), "anchor": "LEGACY",
                         "previous": _text_record(None, None, False), "current": captured, "baseline": anchor,
                         "step": {"status": "UNVERIFIED", "diff": None, "impact": None}, "cumulative": comparison})
        last = writer.index["last"].get(unicodedata.normalize("NFC", key))
        if last is not None and last["anchor"] == "LEGACY" and last["sha256"] == captured["sha256"] and captured["known"]:
            last["record"] = identity


def _capture_md_changes(writer, index, prior, pending, observation, epoch, first):
    root, baseline, current, fingerprints, resumed = observation
    baseline_groups = _watch_groups(baseline["files"])
    current_groups = _watch_groups(current)
    capture = len(index["records"]) + 1
    if first:
        _seed_observation_index(index, prior, baseline_groups)
        index["initialized"] = True
        if index["legacy"]:
            _retain_legacy_pending(writer, prior, root, baseline, baseline_groups, current, epoch, capture)
    scan_issue = any(key.startswith("__SCAN_") or _uninspectable(value) for key, value in current.items())
    ambiguous = {key for key, group in current_groups.items() if len(group) != 1}
    missing_is_reliable = not any(key.startswith("__SCAN_") for key in current)
    gap = []
    if not first and resumed:
        gap.append("MONITORING_RESUMED")
    if (scan_issue or ambiguous) and not index["scan_issue"]:
        gap.append("SCAN_INCOMPLETE")
    if index["storage"] == "WRITE_UNVERIFIED":
        gap.append("RECORDING_INTERRUPTED")
    index["scan_issue"] = bool(scan_issue or ambiguous)
    observations = []
    for key in sorted(index["last"].keys() | current_groups.keys()):
        group = current_groups.get(key, ())
        if key in ambiguous or not group and not missing_is_reliable:
            continue
        previous = index["last"].get(key)
        if group:
            path, digest = group[0]
            if not _is_digest(digest):
                continue
        elif previous is not None:
            path, digest = previous["path"], None
        else:
            continue
        stat_token = fingerprints.get(path)
        if previous is not None and previous["sha256"] == digest:
            if stat_token != previous["stat"] and stat_token is not None and previous["stat"] is not None:
                gap.append("SAME_CONTENT_WRITE_UNCERTAIN")
            anchor = "OBSERVED" if stat_token is not None and previous["anchor"] == "BASELINE" else previous["anchor"]
            index["last"][key] = {**previous, "path": path, "stat": stat_token, "anchor": anchor}
            continue
        observations.append((key, path, digest, stat_token, previous))
    if gap:
        writer.append({"kind": "GAP", "path": None, "notice_id": None,
                       "observed_epoch": epoch, "captured_epoch": epoch, "capture": capture,
                       "reasons": sorted(set(gap))})
    for key, path, digest, stat_token, previous in observations:
        base = _baseline_text(baseline, baseline_groups.get(key))
        before = (_preceding_text(writer.state_dir, index, previous, base) if previous is not None
                  else _text_record(None, "", first or index["has_complete_snapshot"]))
        observed = _observed_text(root, path, digest)
        kind = _change_kind(before["sha256"], digest) if before["known"] else "FIRST_OBSERVED"
        if before["known"] and base["known"] and (previous is None or previous["anchor"] != "BASELINE") and base["sha256"] == digest:
            kind = "RETURNED"
        change = delta({path: base["sha256"]} if base["sha256"] is not None else {},
                       {path: digest} if digest is not None else {}).get(path)
        notice = _notice_id(writer.state_dir, pending, path) if change is not None and pending["changes"].get(path) == change else None
        identity = writer.append({"kind": kind, "path": path, "notice_id": notice,
                                  "observed_epoch": epoch, "captured_epoch": epoch, "capture": capture,
                                  "anchor": previous["anchor"] if previous is not None else "ABSENCE",
                                  "previous": before, "current": observed, "baseline": base,
                                  "step": _observation_comparison(before, observed),
                                  "cumulative": _observation_comparison(base, observed)})
        index["last"][key] = {"path": path, "sha256": digest,
                              "stat": stat_token, "record": identity, "anchor": "OBSERVED"}
    if not scan_issue and not ambiguous:
        index["has_complete_snapshot"] = True
    index["initialized"] = True


def _record_observations(state_dir, prior, pending, observation, epoch):
    root = observation[0]
    try:
        old = _md_index(prior, root, state_dir)
    except StateError:
        return False
    if old["storage"] == "CAPACITY":
        return False
    index = {**old, "records": list(old["records"]), "last": {key: dict(value) for key, value in old["last"].items()}}
    writer = _ObservationWriter(state_dir, index)
    try:
        _capture_md_changes(writer, index, prior, pending, observation, epoch, not old["initialized"])
        if len(_observation_bytes(index)) > MAX_MD_INDEX_BYTES:
            index = {**old, "storage": "CAPACITY"}
        else:
            index["storage"] = None
    except _ObservationCapacity:
        index = {**index, "storage": "CAPACITY"}
    except (OSError, StateError):
        index = {**index, "storage": "WRITE_UNVERIFIED"}
    if len(_observation_bytes(index)) > MAX_MD_INDEX_BYTES:
        index = {**old, "storage": "CAPACITY"}
    if prior.get("md_observations") == index:
        return False
    pending["md_observations"] = index
    return True


def _previous_history_target(root, state_dir):
    saved = read_json(state_dir / "previous-target-review.json", None)
    if saved is None:
        return None
    if (not isinstance(saved, dict) or saved.get("version") != 1
            or not isinstance(saved.get("root"), str) or not isinstance(saved.get("state_dir"), str)
            or not _is_digest(saved.get("registration_SHA256"))):
        raise StateError("Previous monitoring target cannot be verified")
    previous_root, previous_state = Path(saved["root"]), Path(saved["state_dir"])
    if (not previous_root.is_absolute() or ".." in previous_root.parts or not previous_state.is_absolute()
            or previous_state.resolve() != previous_state or previous_state == state_dir or previous_root == root):
        raise StateError("Invalid previous monitoring target")
    return previous_root, previous_state


def _select_history_target(root, state_dir, depth):
    visited = {state_dir}
    for _ in range(depth):
        with _notice_lock(state_dir, shared=True, wait=0.5):
            load_baseline(state_dir, root)
            previous = _previous_history_target(root, state_dir)
        if previous is None or previous[1] in visited:
            raise StateError("Previous monitoring history is unavailable")
        root, state_dir = previous
        visited.add(state_dir)
    return root, state_dir


def _observation_dispositions(state_dir):
    results = {}
    for event in _history(state_dir)["events"]:
        notice = event.get("notice_id")
        if _is_digest(notice):
            if event.get("result") == "ACCEPTED":
                results[notice] = "APPROVED"
            elif event.get("result") == "NOTICE_DISMISSED_UNCONFIRMED" and notice not in results:
                results[notice] = "DISMISSED"
    return results


def _observation_summary(identity, record, outcomes):
    scores = [record.get(mode, {}).get("impact") for mode in ("step", "cumulative")]
    levels = [value["level"] for value in scores if isinstance(value, dict) and type(value.get("level")) is int]
    notice = record["notice_id"]
    approval = "NOT_APPLICABLE" if record["kind"] == "GAP" else "UNAPPROVED"
    if notice is not None:
        approval = "UNVERIFIED" if outcomes is None else outcomes.get(notice, "UNAPPROVED")
    return {"id": identity, "sequence": record["sequence"], "kind": record["kind"], "path": record["path"],
            "observed_epoch": record["observed_epoch"], "capture": record["capture"],
            "approval": approval, "level": max(levels, default=None),
            "text_incomplete": any(record.get(mode, {}).get("status") == "UNVERIFIED" for mode in ("step", "cumulative"))}


def md_history_once(root, state_dir, *, depth=0, before=0, record_id=None):
    root, state_dir = _select_history_target(root, state_dir, depth)
    with _notice_lock(state_dir, shared=True, wait=0.5):
        load_baseline(state_dir, root)
        index = _md_index(_notice_pending(state_dir), root, state_dir)
        try:
            outcomes = _observation_dispositions(state_dir)
        except (OSError, StateError):
            outcomes = None
        records = index["records"]
        if record_id is not None:
            if record_id not in records:
                return {"result": "HISTORY_STALE"}
            event = _read_md_record(state_dir, record_id, index["scope"])
            if event["sequence"] != records.index(record_id) + 1:
                raise StateError("Observation sequence differs")
            return {"result": "HISTORY_EVENT", "entry": _observation_summary(record_id, event, outcomes), "event": event}
        end = min(before - 1, len(records)) if before else len(records)
        start = max(0, end - MD_HISTORY_PAGE)
        rows = []
        for position in range(start, end):
            identity = records[position]
            try:
                event = _read_md_record(state_dir, identity, index["scope"])
                if event["sequence"] != position + 1:
                    raise StateError("Observation sequence differs")
                rows.append(_observation_summary(identity, event, outcomes))
            except (OSError, StateError, KeyError, TypeError):
                rows.append({"id": identity, "sequence": position + 1, "kind": "UNVERIFIED",
                             "path": None, "observed_epoch": None, "capture": None,
                             "approval": "NOT_APPLICABLE", "level": None, "text_incomplete": True})
        has_previous = previous_unverified = False
        if depth < MAX_MD_TARGET_DEPTH:
            try:
                has_previous = _previous_history_target(root, state_dir) is not None
            except (OSError, StateError, ValueError):
                previous_unverified = True
        return {"result": "HISTORY_READY", "root": str(root), "total": len(records), "rows": rows,
                "storage": index["storage"], "legacy": index["legacy"], "incomplete_scans": index["gap_count"],
                "initialized": index["initialized"], "older_before": start + 1 if start else None,
                "is_latest_page": end == len(records), "has_previous": has_previous,
                "previous_unverified": previous_unverified}


def notify(changes, quiet=False):
    names = ", ".join(sorted(changes)[:3])
    message = f"{len(changes)} instruction file(s) changed: {names}"
    result = {
        "console": "EMITTED",
        "desktop": "DISABLED_BY_QUIET" if quiet else "UNAVAILABLE_NON_MACOS",
        "platform": sys.platform,
    }
    if not quiet and sys.platform == "darwin":
        script = 'on run argv\n display notification (item 1 of argv) with title "Orchard Sentinel"\nend run'
        started = time.monotonic()
        try:
            completed = subprocess.run(
                ["/usr/bin/osascript", "-e", script, message],
                check=False,
                timeout=3,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            result["returncode"] = completed.returncode
            result["desktop"] = (
                "REQUEST_ACCEPTED_DELIVERY_UNVERIFIED"
                if completed.returncode == 0
                else "REQUEST_FAILED"
            )
        except subprocess.TimeoutExpired:
            result["desktop"] = "REQUEST_TIMEOUT"
        except OSError as error:
            result["desktop"] = "REQUEST_ERROR:" + type(error).__name__
        result["request_latency_ms"] = round((time.monotonic() - started) * 1000, 3)
    print("[Orchard Sentinel] " + message, flush=True)
    return result


def audit_once(root, state_dir, quiet=False):
    baseline = load_baseline(state_dir, root)
    fingerprints = {}
    current = snapshot(root, fingerprints)
    changes = delta(baseline["files"], current)
    state = record_changes(state_dir, changes, observation=(root, baseline, current, fingerprints, False))
    outstanding = outstanding_changes(state)
    if outstanding:
        result = notify(outstanding, quiet=quiet)
        if not isinstance(result, dict):
            result = {"console": "UNKNOWN", "desktop": "UNKNOWN"}
        mark_notified(state_dir, outstanding, result)
    return changes


class WatchDebouncer:
    """Coalesce observed signatures while retaining evidence before notification."""

    def __init__(self, debounce):
        self.debounce = debounce
        self.previous_signature = None
        self.batch = {}
        self.last_activity = None

    def observe(self, current, outstanding, now_monotonic):
        signature = json.dumps(current, ensure_ascii=True, sort_keys=True)
        transitioned = self.previous_signature is not None and signature != self.previous_signature
        self.previous_signature = signature

        new_evidence = False
        for name, change in outstanding.items():
            if self.batch.get(name) != change:
                self.batch[name] = change
                new_evidence = True
        if new_evidence or (transitioned and self.batch):
            self.last_activity = now_monotonic
        if self.batch and self.last_activity is None:
            self.last_activity = now_monotonic

        if self.batch and now_monotonic - self.last_activity >= self.debounce:
            ready = dict(self.batch)
            self.batch.clear()
            self.last_activity = None
            return ready
        return {}


def watch_until_stopped(root, state_dir, interval=1.0, debounce=2.0, quiet=False,
                        owner_pid=None, run_token=None, registration_file=None):
    """Scan only while this process owns the monitor lease and its app parent lives."""
    token = uuid.uuid4().hex if run_token is None else run_token
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise StateError("Invalid monitor run token")
    if owner_pid is not None and (type(owner_pid) is not int or owner_pid <= 0):
        raise StateError("Invalid monitor owner PID")
    debouncer = WatchDebouncer(debounce)
    resumed = True
    with watch_lease(root, state_dir, registration_file):
        with state_lock(state_dir):
            load_baseline(state_dir, root)
        started = time.time()
        identity = {"version": 1, "root": str(root), "pid": os.getpid(),
                    "owner_pid": owner_pid, "run_token": token, "interval": interval,
                    "started_at_epoch": started, "last_scan_epoch": 0}
        save_json(state_dir / "monitor.json", identity)
        print("Watching local instruction files (polling POC, not a pre-execution enforcement boundary).", flush=True)
        try:
            while True:
                if owner_pid is not None and os.getppid() != owner_pid:
                    print("App owner exited; watcher stopped.", flush=True)
                    break
                with state_lock(state_dir):
                    baseline = load_baseline(state_dir, root)
                    fingerprints = {}
                    current = snapshot(root, fingerprints)
                    changes = delta(baseline["files"], current)
                    state = record_changes(state_dir, changes, observation=(root, baseline, current, fingerprints, resumed))
                    resumed = False
                    outstanding = outstanding_changes(state)
                    ready = debouncer.observe(changes, outstanding, time.monotonic())
                    ready = {name: change for name, change in ready.items()
                             if outstanding.get(name) == change}
                    if ready:
                        result = notify(ready, quiet=quiet)
                        mark_notified(state_dir, ready, result)
                identity["last_scan_epoch"] = time.time()
                save_json(state_dir / "monitor.json", identity)
                control = read_json(state_dir / "monitor-control.json", None)
                if (isinstance(control, dict) and control.get("run_token") == token and
                        control.get("request") == "STOP"):
                    print("Stop requested; pending evidence remains on disk.", flush=True)
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Watch stopped; pending evidence remains on disk.", flush=True)
        finally:
            with state_lock(state_dir):
                current = read_json(state_dir / "monitor.json", None)
                if isinstance(current, dict) and current.get("run_token") == token:
                    _unlink_durable(state_dir / "monitor.json")
                control = read_json(state_dir / "monitor-control.json", None)
                if isinstance(control, dict) and control.get("run_token") == token:
                    _unlink_durable(state_dir / "monitor-control.json")
    return 0


def _resolve_root(path):
    selected = _absolute(path)
    if selected.is_symlink():
        raise SystemExit("--root must not be a symlink")
    try:
        root = selected.resolve(strict=True)
    except FileNotFoundError as error:
        raise SystemExit("--root does not exist") from error
    if not root.is_dir():
        raise SystemExit("--root must be a directory")
    return root


def run(args):
    root = _resolve_root(args.root)
    state_dir = _absolute(args.state_dir)

    if args.command == "registration-preview":
        print(json.dumps(registration_preview(root), ensure_ascii=False))
        return 0

    if args.command == "init":
        if not args.confirm:
            raise SystemExit("Initial trust requires explicit --confirm; do not baseline an unreviewed project.")
        if getattr(args, "fresh_state", False):
            try:
                state_dir.mkdir(mode=0o700)
            except OSError as error:
                raise StateError("A private new monitoring state could not be created") from error
        with state_lock(state_dir):
            baseline_path = state_dir / "baseline.json"
            if _exists_no_follow(baseline_path):
                if baseline_path.is_symlink():
                    raise StateError("Baseline state must not be a symlink")
                if not args.replace:
                    raise SystemExit("Baseline already exists; refusing silent overwrite (use --replace --confirm).")
            files = snapshot(root)
            if getattr(args, "expected_snapshot", None) is not None:
                actual_token = hashlib.sha256(json.dumps(files, sort_keys=True).encode("utf-8")).hexdigest()
                if actual_token != args.expected_snapshot:
                    raise SystemExit("Registration preview is stale; review the current files again.")
            if any(name.startswith("__SCAN_") or _uninspectable(value) for name, value in files.items()):
                raise SystemExit("Cannot trust baseline with unreadable, unstable, or truncated instruction files.")
            review_text = {}
            for name, digest in files.items():
                try:
                    content, checked_digest, _ = _review_file(root, name)
                except ReviewError as error:
                    if str(error) in {"Target exceeds the 64 KiB comparison cap", "Target is not valid UTF-8"}:
                        continue
                    raise SystemExit("Baseline changed or became unreadable during capture") from error
                if checked_digest != digest:
                    raise SystemExit("Baseline changed during comparison capture")
                review_text[name] = content
            if snapshot(root) != files:
                raise SystemExit("Baseline changed during registration")
            empty = _empty_pending()
            previous = read_json(state_dir / "pending.json", None)
            empty["md_observations"] = (previous["md_observations"] if isinstance(previous, dict) and
                                        "md_observations" in previous else _empty_md_index(root, state_dir, legacy=False))
            save_json(
                baseline_path,
                {"version": 3, "root": str(root), "files": files,
                 "review_text": review_text, "asof_epoch": time.time()},
            )
            save_json(state_dir / "pending.json", empty)
        print(f"Baseline saved: {len(files)} files. No files uploaded or executed.")
        return 0

    if args.command == "notice-list":
        print(json.dumps(notice_list_once(root, state_dir), ensure_ascii=False))
        return 0
    if args.command in {"md-history", "md-history-event"}:
        value = md_history_once(root, state_dir, depth=args.history_depth, before=args.history_before,
                                record_id=args.history_record)
        print(json.dumps(value, ensure_ascii=False))
        return 0 if value["result"] in {"HISTORY_READY", "HISTORY_EVENT"} else 3
    if args.notice_id is None:
        ensure_state_dir(state_dir, create=False)
    if args.command == "check":
        with state_lock(state_dir):
            changes = audit_once(root, state_dir, quiet=args.quiet)
            pending = load_pending(state_dir)
        print(
            json.dumps(
                {
                    "changes": changes,
                    "pending": pending["changes"],
                    "last_notification": pending.get("last_notification"),
                },
                ensure_ascii=False,
            )
        )
        return 2 if changes else 0
    if args.command == "watch":
        return watch_until_stopped(root, state_dir, args.interval, args.debounce,
                                   args.quiet, getattr(args, "owner_pid", None),
                                   getattr(args, "run_token", None),
                                   getattr(args, "registration_file", None))
    if args.command == "monitor-status":
        print(json.dumps(monitor_status_once(root, state_dir), ensure_ascii=False))
        return 0
    if args.command == "monitor-stop":
        if not args.run_token:
            raise SystemExit("monitor-stop requires the observed --run-token")
        outcome = monitor_stop_once(root, state_dir, args.run_token)
        print(json.dumps(outcome, ensure_ascii=False))
        return 0 if outcome["result"] == "STOP_REQUESTED" else 3
    if args.command == "pending":
        with state_lock(state_dir):
            load_baseline(state_dir, root)
            print(json.dumps(load_pending(state_dir), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.command == "review":
        if not (args.path or args.notice_id):
            raise SystemExit("review requires a target")
        try:
            review = review_once(root, state_dir, args.path, args.notice_id)
        except ReviewError as error:
            print(json.dumps({"result": "REFUSED", "reason": str(error)}, ensure_ascii=False))
            return 3
        print(json.dumps(review if review is not None else {"result": "NOTICE_STALE"}, ensure_ascii=False))
        return 0 if review is not None and review.get("result") != "REFUSED" else 3
    if args.command == "accept":
        if not ((args.path or args.notice_id) and args.review_token and args.reviewed_after and
                args.reviewed_before is not None and args.human_confirmed):
            raise SystemExit("accept requires reviewed identity and explicit --human-confirmed")
        before = None if args.reviewed_before == "NONE" else args.reviewed_before
        outcome = accept_once(root, state_dir, args.path, args.review_token,
                              before, args.reviewed_after, args.notice_id)
        print(json.dumps(outcome, ensure_ascii=False))
        return 0 if outcome["result"] == "ACCEPTED" else 3
    if args.command == "claim-alert":
        if args.notice_id is None and not (args.path and args.reviewed_after and args.detected_at is not None and
                math.isfinite(args.detected_at) and args.detected_at >= 0):
            raise SystemExit("claim-alert requires path, current hash, and detection time")
        after = None if args.reviewed_after == "NONE" else args.reviewed_after
        outcome = claim_alert_once(root, state_dir, args.path, after,
                                   args.detected_at, args.notice_id)
        print(json.dumps(outcome, ensure_ascii=False))
        return 0
    if args.command == "dismiss-notice":
        if not (args.notice_id and args.human_confirmed):
            raise SystemExit("dismiss-notice requires a notice ID and explicit confirmation")
        outcome = dismiss_notice_once(root, state_dir, args.notice_id)
        print(json.dumps(outcome, ensure_ascii=False))
        return 0 if outcome["result"] != "NOTICE_STALE" else 3
    raise SystemExit("Unknown command")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["registration-preview", "init", "check", "watch",
                                            "monitor-status", "monitor-stop", "pending",
                                            "review", "accept", "claim-alert", "notice-list", "dismiss-notice",
                                            "md-history", "md-history-event"])
    parser.add_argument("--root", required=True, help="Explicit directory to monitor")
    parser.add_argument("--state-dir", default="~/Library/Application Support/OrchardSentinelPoC")
    parser.add_argument("--confirm", action="store_true", help="Human explicitly reviewed initial baseline")
    parser.add_argument("--expected-snapshot", help="Exact token from a registration preview")
    parser.add_argument("--replace", action="store_true", help="Replace an existing baseline (with --confirm)")
    parser.add_argument("--fresh-state", action="store_true", help="Require a new state directory for a folder switch")
    parser.add_argument("--quiet", action="store_true", help="Disable macOS desktop notification")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--debounce", type=float, default=2.0)
    parser.add_argument("--path", help="One relative watched path for review or accept")
    parser.add_argument("--notice-id", help="Exact ID from the committed pending notice list")
    parser.add_argument("--history-depth", type=int, default=0, help="User-selected saved monitoring target")
    parser.add_argument("--history-before", type=int, default=0, help="Exclusive observation sequence for the older page")
    parser.add_argument("--history-record", help="Exact immutable observation identity")
    parser.add_argument("--review-token", help="Exact identity returned by review")
    parser.add_argument("--reviewed-before", help="Reviewed baseline hash, or NONE for addition")
    parser.add_argument("--reviewed-after", help="Reviewed current hash")
    parser.add_argument("--human-confirmed", action="store_true", help="UI explicit approval only")
    parser.add_argument("--detected-at", type=float, help="Exact pending event detection epoch")
    parser.add_argument("--owner-pid", type=int, help="App PID; watcher exits when reparented")
    parser.add_argument("--run-token", help="Exact watch run identity for start or stop")
    parser.add_argument("--registration-file", type=Path, help="Current registration for app watcher admission")
    args = parser.parse_args()
    if args.interval <= 0 or args.debounce < 0:
        parser.error("interval must be positive and debounce nonnegative")
    if args.notice_id is not None and (args.path is not None
            or not re.fullmatch(r"[0-9a-f]{64}", args.notice_id)
            or args.command not in {"review", "accept", "claim-alert", "dismiss-notice"}):
        parser.error("--notice-id must identify one current notice")
    if (not 0 <= args.history_depth <= MAX_MD_TARGET_DEPTH or args.history_before < 0
            or args.command == "md-history-event" and not _is_digest(args.history_record)
            or args.command != "md-history-event" and args.history_record is not None
            or args.command not in {"md-history", "md-history-event"} and (args.history_depth or args.history_before)):
        parser.error("Invalid observation history selection")
    try:
        code = run(args)
    except (OSError, StateError) as error:
        if isinstance(error, NoticeBusy):
            print(json.dumps({"result": "NOTICE_BUSY"}))
            code = 3
        elif args.command in {"md-history", "md-history-event"}:
            print(json.dumps({"result": "HISTORY_UNVERIFIED"}))
            code = 3
        elif args.command in {"review", "accept", "notice-list", "dismiss-notice"}:
            print(json.dumps({"result": "REFUSED", "reason": "Saved review state cannot be verified"}))
            code = 3
        elif isinstance(error, StateError):
            raise SystemExit(f"State error: {error}") from error
        else:
            raise
    raise SystemExit(code)


if __name__ == "__main__":
    main()
