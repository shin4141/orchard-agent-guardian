"""Validate registration, publish confirmed targets, and coordinate watcher admission.

Baseline, pending and history are never written by this helper.
"""
import argparse
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

CAP = 8 * 1024 * 1024
POINTER_CAP = 16384
REVIEW_STATE_LOCK_WAIT = 0.5
SENTINEL = Path(__file__).with_name('sentinel.py')
R2 = 'Private100KCandidate7'
PREVIEW = 'Private300KCandidate11'
MESSAGES = {
    'REGISTRATION_INVALID': '登録情報の形式を確認できません。旧版の登録と保存先を確認し、元のファイルを削除せず再確認してください。',
    'STATE_INVALID': '基準・未確認変更・承認履歴の互換性を確認できません。旧版で保存状態を確認してください。自動初期化は行いません。',
    'STATE_BUSY': '旧版または別のOrchardが保存状態を更新中です。処理終了後に登録を再確認してください。',
    'OLD_MONITOR_RUNNING': '旧版または別のOrchardが監視中です。そちらで監視を停止して終了した後、登録を再確認してください。二重監視は開始しません。',
    'MONITOR_INVALID': '以前の監視状態を確認できません。旧版の監視状態を確認して終了した後、登録を再確認してください。',
    'ACCEPTANCE_INCOMPLETE': '承認処理の中断記録があります。旧版で状態を確認して終了してください。未確認変更の自動承認・初期化は行いません。',
    'REGISTRATION_CHANGED': '確認中に登録情報が変わりました。既存登録を保持したまま、もう一度登録を確認してください。',
    'SWITCH_EVIDENCE_UNAVAILABLE': '旧監視先の未確認原文と差分を安全に保存できません。旧登録と記録を保持しました。未確認の変更を確認してから再試行してください。',
    'SWITCH_OUTCOME_UNVERIFIED': '切替結果を確認できません。監視を開始せず、保存済みの登録を再確認してください。',
    'REGISTRATION_DIRECTORY_PERMISSIONS': '登録の保存フォルダまたはその親のアクセス権を確認できません。元のファイルを残し、Finderで保存フォルダとその親の所有者・アクセス権を確認してください。',
    'PATH_UNSAFE': '登録または保存先の実体・所有者・アクセス権を確認できません。旧版の保存先を確認し、元の記録は保持してください。',
    'PREVIEW_CONFIRMATION_REQUIRED': '別の保存先に以前の登録が見つかりました。公開版の登録とは区別し、内容を確認してから引き継いでください。',
    'IO_ERROR': '登録情報を安全に読み取れません。既存の記録を保持しています。保存先を確認して再確認してください。',
}


def checkpoint(name):
    # Fixed phase labels only: never output paths, state contents or hashes.
    print('ORCHARD_CONTINUITY_PHASE:' + name, file=sys.stderr, flush=True)


class Hold(ValueError):
    pass


def need(ok, code):
    if not ok: raise Hold(code)


def exists(p): return os.path.lexists(p)


def safe_path(value, directory=False, private=False):
    need(type(value) is str and value.startswith('/') and len(value.encode()) <= 4096
         and not any(ord(x) < 32 or ord(x) == 127 or '\u202a' <= x <= '\u202e' or '\u2066' <= x <= '\u2069' for x in value), 'PATH_UNSAFE')
    p = Path(value)
    need(str(p) == os.path.normpath(value) and str(p) == os.path.realpath(value), 'PATH_UNSAFE')
    for parent in p.parents:
        if exists(parent):
            st = parent.lstat(); need(stat.S_ISDIR(st.st_mode), 'PATH_UNSAFE')
    if directory:
        st = p.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid(), 'PATH_UNSAFE')
        if private: need(stat.S_IMODE(st.st_mode) == 0o700, 'PATH_UNSAFE')
    return p


def read_bytes(p, cap=CAP):
    safe_path(str(p))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.getuid()
             and not st.st_mode & 0o077 and 0 <= st.st_size <= cap, 'PATH_UNSAFE')
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(cap + 1)
        end = os.fstat(fd)
        need(len(raw) == st.st_size and len(raw) <= cap and
             (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
             (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns, end.st_ctime_ns), 'REGISTRATION_CHANGED')
        return raw
    finally: os.close(fd)


def registration_directory(path):
    directory = safe_path(str(path), directory=True)
    mode = stat.S_IMODE(directory.lstat().st_mode)
    if mode == 0o755:
        # Legacy App Support containers can be traversable only within an owner-private parent.
        try:
            safe_path(str(directory.parent), directory=True, private=True)
        except Hold:
            raise Hold('REGISTRATION_DIRECTORY_PERMISSIONS') from None
    else:
        need(mode == 0o700, 'REGISTRATION_DIRECTORY_PERMISSIONS')
    return directory


def object_pairs(pairs):
    value = {}
    for k, v in pairs:
        need(k not in value, 'STATE_INVALID'); value[k] = v
    return value


def obj(raw):
    try:
        value = json.loads(raw, object_pairs_hook=object_pairs, parse_constant=lambda _: (_ for _ in ()).throw(Hold('STATE_INVALID')))
    except (UnicodeError, json.JSONDecodeError): raise Hold('STATE_INVALID') from None
    need(type(value) is dict, 'STATE_INVALID')
    return value


@contextmanager
def lock_file(path, *, shared=False, create=False, busy='STATE_BUSY', allow_busy=False,
              registration=False, wait_seconds=0):
    safe_path(str(path))
    if registration:
        registration_directory(path.parent)
    else:
        safe_path(str(path.parent), directory=True, private=True)
    if not exists(path) and not create:
        yield None; return
    flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDWR | os.O_CREAT if create else os.O_RDONLY)
    fd = os.open(path, flags, 0o600)
    locked = False
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
             and not st.st_mode & 0o077, 'PATH_UNSAFE')
        flags = (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, flags)
                locked = True
                break
            except BlockingIOError:
                if allow_busy:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Hold(busy) from None
                time.sleep(min(0.025, remaining))
        yield locked
    finally:
        if locked: fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def sentinel_module():
    spec = importlib.util.spec_from_file_location('orchard_unchanged_sentinel_reader', SENTINEL)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def finite(value): return type(value) in (int, float) and math.isfinite(value) and value >= 0


def state_snapshot(state, root):
    checkpoint('STATE_SCHEMA')
    need(not exists(state / 'accept-journal.json'), 'ACCEPTANCE_INCOMPLETE')
    need(exists(state / 'baseline.json') and exists(state / 'pending.json'), 'STATE_INVALID')
    names = ['baseline.json', 'pending.json'] + (['history.json'] if exists(state / 'history.json') else [])
    raw = {n: read_bytes(state / n) for n in names}
    values = {n: obj(v) for n, v in raw.items()}
    need(values['baseline.json'].get('version') in (1, 2, 3) and type(values['baseline.json'].get('version')) is int
         and values['pending.json'].get('version') in (1, 2, 3) and type(values['pending.json'].get('version')) is int, 'STATE_INVALID')
    need(type(values['pending.json'].get('changes')) is dict, 'STATE_INVALID')
    if values['pending.json']['version'] == 3:
        need(all(type(values['pending.json'].get(k)) is dict for k in
                 ('detected_at_epoch', 'last_observed_changes', 'unnotified_changes')), 'STATE_INVALID')
    if 'history.json' in values: need(type(values['history.json'].get('version')) is int and values['history.json']['version'] == 1, 'STATE_INVALID')
    checkpoint('READER_IMPORT')
    s = sentinel_module()
    checkpoint('READER_VALIDATE')
    try:
        baseline = s.load_baseline(state, root); pending = s.load_pending(state); history = s._history(state)
    except s.StateError: raise Hold('STATE_INVALID') from None
    need(len(baseline['files']) <= 1025 and len(pending['changes']) <= 1025, 'STATE_INVALID')
    for name, digest in baseline['files'].items():
        need(type(name) is str and not name.startswith('/') and '..' not in Path(name).parts
             and type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest) is not None, 'STATE_INVALID')
    for name in pending['changes']:
        need(not name.startswith('/') and '..' not in Path(name).parts, 'STATE_INVALID')
    need(all(hashlib.sha256(text.encode('utf-8')).hexdigest() == baseline['files'][name]
             for name, text in baseline.get('review_text', {}).items()), 'STATE_INVALID')
    need(all(read_bytes(state / n) == v for n, v in raw.items()), 'REGISTRATION_CHANGED')
    return {'pending_count': len(pending['changes']), 'history_count': len(history['events']),
            'state_file_SHA256': {n: hashlib.sha256(v).hexdigest() for n, v in raw.items()}}


def monitor_state(state, root, locked, owned_pid=None, owner_pid=None):
    heartbeat = obj(read_bytes(state / 'monitor.json')) if exists(state / 'monitor.json') else None
    if heartbeat is not None:
        need(heartbeat.get('version') == 1 and heartbeat.get('root') == str(root)
             and type(heartbeat.get('pid')) is int and heartbeat['pid'] > 0
             and type(heartbeat.get('run_token')) is str and re.fullmatch('[0-9a-f]{32}', heartbeat['run_token'])
             and finite(heartbeat.get('interval')) and heartbeat['interval'] > 0
             and finite(heartbeat.get('last_scan_epoch')), 'MONITOR_INVALID')
    if locked is False:
        own = heartbeat is not None and owned_pid is not None and owner_pid is not None and heartbeat['pid'] == owned_pid and heartbeat.get('owner_pid') == owner_pid
        need(own, 'OLD_MONITOR_RUNNING')
        age = time.time() - heartbeat['last_scan_epoch']
        need(0 <= age <= max(5, 3 * heartbeat['interval']), 'MONITOR_INVALID')
        return 'OWNED_RUNNING'
    if heartbeat is not None:
        try: os.kill(heartbeat['pid'], 0)
        except ProcessLookupError: pass
        except PermissionError: raise Hold('MONITOR_INVALID') from None
        else: raise Hold('MONITOR_INVALID')
    if exists(state / 'monitor-control.json'):
        control = obj(read_bytes(state / 'monitor-control.json'))
        need(control.get('request') == 'STOP' and type(control.get('run_token')) is str
             and re.fullmatch('[0-9a-f]{32}', control['run_token']), 'MONITOR_INVALID')
    return 'STOPPED'


def publish_pointer(target, root, state, retired):
    value = {'version': 1, 'root': str(root), 'state_dir': str(state)}
    if retired:
        value['retired_state_dirs'] = list(map(str, retired))
    payload = (json.dumps(value, sort_keys=True) + '\n').encode()
    need(len(payload) <= POINTER_CAP, 'REGISTRATION_INVALID')
    staged = stage_pointer(target, payload)
    try:
        # No replacement: an existing, even invalid, pointer is never erased.
        try: os.link(staged, target, follow_symlinks=False)
        except FileExistsError: raise Hold('REGISTRATION_CHANGED') from None
    finally:
        staged.unlink()
    fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    readback = read_bytes(target, POINTER_CAP)
    need(readback == payload, 'REGISTRATION_CHANGED')
    return readback


def read_registration(source):
    raw = read_bytes(source, POINTER_CAP)
    try: saved = obj(raw)
    except Hold: raise Hold('REGISTRATION_INVALID') from None
    need(type(saved.get('version')) is int and saved['version'] == 1
         and type(saved.get('root')) is str and type(saved.get('state_dir')) is str, 'REGISTRATION_INVALID')
    return raw, saved


def registration_paths(saved):
    root = safe_path(saved['root'], directory=True)
    state = safe_path(saved['state_dir'], directory=True, private=True)
    need(root != state and not state.is_relative_to(root), 'PATH_UNSAFE')
    return root, state


def retired_states(saved, current):
    # Earlier builds can enter a watcher after having checked the old pointer.
    # Keep their per-state leases covered while a newer target is monitored.
    values = saved.get('retired_state_dirs', [])
    need(type(values) is list and all(type(path) is str for path in values)
         and len(set(values)) == len(values) and str(current) not in values, 'REGISTRATION_INVALID')
    return [safe_path(value, directory=True, private=True) for value in values]


def hold_retired_leases(stack, states):
    for state in states:
        lease = stack.enter_context(lock_file(state / 'monitor.lock', busy='OLD_MONITOR_RUNNING'))
        need(lease is True, 'MONITOR_INVALID')


@contextmanager
def registered_monitor_lease(registration, root, state):
    target = safe_path(str(registration))
    with ExitStack() as leases:
        with lock_file(target.parent / '.registration.lock', create=True, registration=True):
            _, saved = read_registration(target)
            need((root, state) == registration_paths(saved), 'REGISTRATION_CHANGED')
            hold_retired_leases(leases, retired_states(saved, state))
            lease = leases.enter_context(lock_file(state / 'monitor.lock', create=True, busy='OLD_MONITOR_RUNNING'))
            monitor_state(state, root, lease)
        yield


def validate_source(source, canonical, origin, *, publish=False, expected=None, owned_pid=None,
                    owner_pid=None, state_lock_wait=0):
    checkpoint('REGISTRY')
    raw, saved = read_registration(source)
    if expected is not None: need(hashlib.sha256(raw).hexdigest() == expected, 'REGISTRATION_CHANGED')
    root, state = registration_paths(saved)
    retired = retired_states(saved, state)
    need(exists(state / 'state.lock'), 'STATE_INVALID')
    with lock_file(state / 'state.lock', shared=True, wait_seconds=state_lock_wait):
        snapshot = state_snapshot(state, root)
        checkpoint('MONITOR_LEASE')
        with ExitStack() as locks:
            locked = locks.enter_context(lock_file(state / 'monitor.lock', create=publish, allow_busy=True))
            monitor = monitor_state(state, root, locked, owned_pid, owner_pid)
            if monitor == 'STOPPED':
                hold_retired_leases(locks, retired)
            need(not publish or monitor == 'STOPPED', 'OLD_MONITOR_RUNNING')
            need(read_bytes(source, POINTER_CAP) == raw, 'REGISTRATION_CHANGED')
            if publish:
                checkpoint('POINTER_PUBLISH')
                raw = publish_pointer(canonical, root, state, retired)
    return dict(status='READY', origin=origin, root=str(root), state_dir=str(state), monitor=monitor,
                registration_SHA256=hashlib.sha256(raw).hexdigest(), **snapshot)


def stage_pointer(target, payload):
    fd, name = tempfile.mkstemp(prefix='.registration-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(name)
        raise
    return Path(name)


def replace_pointer(target, old, payload):
    need(len(payload) <= POINTER_CAP, 'SWITCH_OUTCOME_UNVERIFIED')
    with ExitStack() as cleanup:
        staged = stage_pointer(target, payload)
        cleanup.callback(staged.unlink, missing_ok=True)
        backup = stage_pointer(target, old)
        cleanup.callback(backup.unlink, missing_ok=True)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        cleanup.callback(os.close, directory)
        identity = staged.lstat()
        os.fsync(directory)
        need(read_bytes(target, POINTER_CAP) == old, 'REGISTRATION_CHANGED')
        os.replace(staged, target)
        try:
            need(read_bytes(target, POINTER_CAP) == payload, 'SWITCH_OUTCOME_UNVERIFIED')
            os.fsync(directory)
        except (OSError, Hold):
            try:
                actual = target.lstat()
                need((actual.st_dev, actual.st_ino) == (identity.st_dev, identity.st_ino),
                     'SWITCH_OUTCOME_UNVERIFIED')
                os.replace(backup, target)
                os.fsync(directory)
                need(read_bytes(target, POINTER_CAP) == old, 'SWITCH_OUTCOME_UNVERIFIED')
            except (OSError, Hold):
                raise Hold('SWITCH_OUTCOME_UNVERIFIED') from None
            raise Hold('IO_ERROR') from None


def switch_target(canonical, action, expected, root, state, new_root, new_state, preview):
    raw, saved = read_registration(canonical)
    current_root, current_state = registration_paths(saved)
    token = hashlib.sha256(raw).hexdigest()
    need((root, state) == (str(current_root), str(current_state)) and expected == token,
         'REGISTRATION_CHANGED')
    retired = retired_states(saved, current_state)
    with ExitStack() as locks:
        hold_retired_leases(locks, retired)
        lease = locks.enter_context(lock_file(current_state / 'monitor.lock', create=action == 'switch',
                                              busy='OLD_MONITOR_RUNNING'))
        monitor_state(current_state, current_root, lease)
        need(exists(current_state / 'state.lock'), 'STATE_INVALID')
        locks.enter_context(lock_file(current_state / 'state.lock', shared=True))
        previous = state_snapshot(current_state, current_root)
        if action == 'switch-check':
            return dict(status='READY', origin='CURRENT', root=root, state_dir=state, monitor='STOPPED',
                        registration_SHA256=token, **previous)

        next_root, next_state = registration_paths({'root': new_root, 'state_dir': new_state})
        need(next_root != current_root and next_state != current_state and next_state not in retired
             and next_state.parent == canonical.parent
             and re.fullmatch(r'state-[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}', next_state.name),
             'PATH_UNSAFE')
        lease = locks.enter_context(lock_file(next_state / 'monitor.lock', create=True, busy='OLD_MONITOR_RUNNING'))
        monitor_state(next_state, next_root, lease)
        need(exists(next_state / 'state.lock'), 'STATE_INVALID')
        locks.enter_context(lock_file(next_state / 'state.lock'))
        candidate = state_snapshot(next_state, next_root)
        need(candidate['pending_count'] == candidate['history_count'] == 0, 'STATE_INVALID')
        s = sentinel_module()
        baseline = s.load_baseline(next_state, next_root)
        baseline_token = hashlib.sha256(json.dumps(baseline['files'], sort_keys=True).encode('utf-8')).hexdigest()
        need(preview == baseline_token, 'REGISTRATION_CHANGED')
        archive = {'version': 1, 'root': root, 'state_dir': state, 'registration_SHA256': token, **previous}
        try:
            archive['pending_reviews'] = s.pending_review_archive(current_root, current_state, CAP)
            evidence = next_state / 'previous-target-review.json'
            s.save_json(evidence, archive)
        except (s.ReviewError, s.StateError):
            raise Hold('SWITCH_EVIDENCE_UNAVAILABLE') from None
        need(obj(read_bytes(evidence)) == archive, 'SWITCH_EVIDENCE_UNAVAILABLE')
        try:
            need(s.registration_preview(next_root)['snapshot_token'] == preview, 'REGISTRATION_CHANGED')
        except (s.ReviewError, s.StateError):
            raise Hold('REGISTRATION_CHANGED') from None
        payload = (json.dumps({'version': 1, 'root': new_root, 'state_dir': new_state,
                               'retired_state_dirs': [*map(str, retired), state]}, sort_keys=True) + '\n').encode()
        checkpoint('POINTER_PUBLISH')
        replace_pointer(canonical, raw, payload)
        return dict(status='READY', origin='SWITCH', root=new_root, state_dir=new_state, monitor='STOPPED',
                    registration_SHA256=hashlib.sha256(payload).hexdigest(), **candidate)


def resolve(registration, action='resolve', *, expected=None, root=None, state=None, owned_pid=None,
            owner_pid=None, new_root=None, new_state=None, preview=None, run_token=None,
            wait_review_lock=False):
    canonical = safe_path(str(registration)); parent = canonical.parent
    legacy = parent / R2 / 'registration.json'; preview_registration = parent / PREVIEW / 'registration.json'
    switching = action in ('switch-check', 'switch')
    if switching or action in ('current', 'switch-stop'):
        need(exists(canonical), 'REGISTRATION_CHANGED')
    if not exists(parent):
        need(action != 'save', 'PATH_UNSAFE')
        return {'status': 'UNREGISTERED', 'origin': 'NONE'}
    registration_directory(parent)
    if not any(exists(p) for p in (canonical, legacy, preview_registration)) and action != 'save':
        return {'status': 'UNREGISTERED', 'origin': 'NONE'}
    with lock_file(parent / '.registration.lock', create=True, registration=True):
        if switching:
            need(exists(canonical), 'REGISTRATION_CHANGED')
            return switch_target(canonical, action, expected, root, state, new_root, new_state, preview)
        if action == 'adopt-preview':
            need(not exists(canonical) and not exists(legacy) and exists(preview_registration), 'REGISTRATION_CHANGED')
            need(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected), 'PREVIEW_CONFIRMATION_REQUIRED')
            return validate_source(preview_registration, canonical, 'PREVIEW11', publish=True, expected=expected)
        if exists(canonical):
            result = validate_source(canonical, canonical, 'CURRENT',
                                     expected=expected if action == 'switch-stop' else None,
                                     owned_pid=owned_pid, owner_pid=owner_pid,
                                     state_lock_wait=REVIEW_STATE_LOCK_WAIT if wait_review_lock else 0)
            if action in ('check', 'save', 'switch-stop'):
                need(root == result['root'] and state == result['state_dir'], 'REGISTRATION_CHANGED')
            if action == 'switch-stop':
                need(expected is not None and result['monitor'] == 'OWNED_RUNNING'
                     and type(run_token) is str and re.fullmatch('[0-9a-f]{32}', run_token), 'MONITOR_INVALID')
                s = sentinel_module()
                try:
                    outcome = s.monitor_stop_once(Path(root), Path(state), run_token)
                except s.StateError:
                    raise Hold('MONITOR_INVALID') from None
                need(outcome.get('run_token') == run_token and outcome.get('result') == 'STOP_REQUESTED',
                     'MONITOR_INVALID')
                result['monitor'] = 'STOP_REQUESTED'
            return result
        if action == 'save':
            # Initial registration was explicitly confirmed in the product UI.
            need(not exists(legacy) and not exists(preview_registration), 'REGISTRATION_CHANGED')
            source = parent / ('.new-registration-' + os.urandom(8).hex())
            try:
                fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as f: json.dump({'version': 1, 'root': root, 'state_dir': state}, f)
                return validate_source(source, canonical, 'NEW', publish=True)
            finally:
                if exists(source): source.unlink()
        need(action not in ('check', 'current', 'switch-stop'), 'REGISTRATION_CHANGED')
        if exists(legacy): return validate_source(legacy, canonical, 'R2', publish=True)
        if exists(preview_registration):
            result = validate_source(preview_registration, canonical, 'PREVIEW11')
            result.update(status='CHOICE', reason='PREVIEW_CONFIRMATION_REQUIRED', message=MESSAGES['PREVIEW_CONFIRMATION_REQUIRED'])
            return result
        need(action != 'adopt-preview', 'REGISTRATION_CHANGED')
        return {'status': 'UNREGISTERED', 'origin': 'NONE'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['resolve', 'adopt-preview', 'check', 'save', 'current',
                                     'switch-stop', 'switch-check', 'switch'])
    p.add_argument('--registration-file', type=Path, required=True)
    p.add_argument('--expected'); p.add_argument('--root'); p.add_argument('--state-dir')
    p.add_argument('--new-root'); p.add_argument('--new-state-dir'); p.add_argument('--reviewed-snapshot')
    p.add_argument('--owned-pid', type=int); p.add_argument('--owner-pid', type=int); p.add_argument('--run-token')
    p.add_argument('--wait-review-lock', action='store_true', help='Bounded shared-lock wait before review or acceptance')
    a = p.parse_args(argv)
    if a.wait_review_lock and a.action != 'check':
        p.error('--wait-review-lock requires check')
    checkpoint('START')
    try:
        if a.owner_pid is not None: need(a.owner_pid == os.getppid(), 'MONITOR_INVALID')
        result = resolve(a.registration_file, a.action, expected=a.expected, root=a.root, state=a.state_dir,
                         owned_pid=a.owned_pid, owner_pid=a.owner_pid, new_root=a.new_root, new_state=a.new_state_dir,
                         preview=a.reviewed_snapshot, run_token=a.run_token, wait_review_lock=a.wait_review_lock)
    except Hold as error:
        code = str(error); result = {'status': 'HOLD', 'reason': code, 'message': MESSAGES.get(code, MESSAGES['IO_ERROR'])}
    except (OSError, ValueError, KeyError, TypeError):
        result = {'status': 'HOLD', 'reason': 'IO_ERROR', 'message': MESSAGES['IO_ERROR']}
    checkpoint('DONE')
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
