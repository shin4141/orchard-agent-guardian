"""Version-independent registration pointer; never migrate or approve state.

Uses the unchanged Sentinel readers under shared state locks. Adoption only
publishes a new pointer; baseline, pending and history are never written here.
No network, scheduler, watched-file execution or monitor start entry exists.
"""
import argparse
from contextlib import contextmanager
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
def lock_file(path, *, shared=False, create=False, busy='STATE_BUSY', allow_busy=False):
    safe_path(str(path)); safe_path(str(path.parent), directory=True, private=True)
    if not exists(path) and not create:
        yield None; return
    flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDWR | os.O_CREAT if create else os.O_RDONLY)
    fd = os.open(path, flags, 0o600)
    locked = False
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and st.st_nlink == 1
             and not st.st_mode & 0o077, 'PATH_UNSAFE')
        try:
            fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB); locked = True
        except BlockingIOError:
            if not allow_busy: raise Hold(busy) from None
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


def publish_pointer(target, root, state):
    payload = (json.dumps({'version': 1, 'root': str(root), 'state_dir': str(state)}, sort_keys=True) + '\n').encode()
    fd, name = tempfile.mkstemp(prefix='.registration-', dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f: f.write(payload); f.flush(); os.fsync(f.fileno())
        # No replacement: an existing, even invalid, pointer is never erased.
        try: os.link(name, target, follow_symlinks=False)
        except FileExistsError: raise Hold('REGISTRATION_CHANGED') from None
    finally:
        os.unlink(name)
    fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def validate_source(source, canonical, origin, *, publish=False, expected=None, owned_pid=None, owner_pid=None):
    checkpoint('REGISTRY')
    raw = read_bytes(source, 16384)
    try: saved = obj(raw)
    except Hold: raise Hold('REGISTRATION_INVALID') from None
    need(type(saved.get('version')) is int and saved['version'] == 1
         and type(saved.get('root')) is str and type(saved.get('state_dir')) is str, 'REGISTRATION_INVALID')
    if expected is not None: need(hashlib.sha256(raw).hexdigest() == expected, 'REGISTRATION_CHANGED')
    root = safe_path(saved['root'], directory=True); state = safe_path(saved['state_dir'], directory=True, private=True)
    need(root != state and not state.is_relative_to(root), 'PATH_UNSAFE')
    need(exists(state / 'state.lock'), 'STATE_INVALID')
    with lock_file(state / 'state.lock', shared=True):
        snapshot = state_snapshot(state, root)
        checkpoint('MONITOR_LEASE')
        with lock_file(state / 'monitor.lock', create=publish, allow_busy=True) as locked:
            monitor = monitor_state(state, root, locked, owned_pid, owner_pid)
            need(not publish or monitor == 'STOPPED', 'OLD_MONITOR_RUNNING')
            need(read_bytes(source, 16384) == raw, 'REGISTRATION_CHANGED')
            if publish:
                checkpoint('POINTER_PUBLISH')
                publish_pointer(canonical, root, state)
    return dict(status='READY', origin=origin, root=str(root), state_dir=str(state), monitor=monitor,
                registration_SHA256=hashlib.sha256(raw).hexdigest(), **snapshot)


def resolve(registration, action='resolve', *, expected=None, root=None, state=None, owned_pid=None, owner_pid=None):
    canonical = safe_path(str(registration)); parent = canonical.parent
    legacy = parent / R2 / 'registration.json'; preview = parent / PREVIEW / 'registration.json'
    if not exists(parent):
        need(action != 'save', 'PATH_UNSAFE')
        return {'status': 'UNREGISTERED', 'origin': 'NONE'}
    safe_path(str(parent), directory=True, private=True)
    if not any(exists(p) for p in (canonical, legacy, preview)) and action != 'save':
        return {'status': 'UNREGISTERED', 'origin': 'NONE'}
    with lock_file(parent / '.registration.lock', create=True):
        if action == 'adopt-preview':
            need(not exists(canonical) and not exists(legacy) and exists(preview), 'REGISTRATION_CHANGED')
            need(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected), 'PREVIEW_CONFIRMATION_REQUIRED')
            return validate_source(preview, canonical, 'PREVIEW11', publish=True, expected=expected)
        if exists(canonical):
            result = validate_source(canonical, canonical, 'CURRENT', owned_pid=owned_pid, owner_pid=owner_pid)
            if action in ('check', 'save'):
                need(root == result['root'] and state == result['state_dir'], 'REGISTRATION_CHANGED')
            return result
        if action == 'save':
            # Initial registration was explicitly confirmed in the product UI.
            need(not exists(legacy) and not exists(preview), 'REGISTRATION_CHANGED')
            source = parent / ('.new-registration-' + os.urandom(8).hex())
            try:
                fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as f: json.dump({'version': 1, 'root': root, 'state_dir': state}, f)
                return validate_source(source, canonical, 'NEW', publish=True)
            finally:
                if exists(source): source.unlink()
        need(action != 'check', 'REGISTRATION_CHANGED')
        if exists(legacy): return validate_source(legacy, canonical, 'R2', publish=True)
        if exists(preview):
            result = validate_source(preview, canonical, 'PREVIEW11')
            result.update(status='CHOICE', reason='PREVIEW_CONFIRMATION_REQUIRED', message=MESSAGES['PREVIEW_CONFIRMATION_REQUIRED'])
            return result
        need(action != 'adopt-preview', 'REGISTRATION_CHANGED')
        return {'status': 'UNREGISTERED', 'origin': 'NONE'}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['resolve', 'adopt-preview', 'check', 'save'])
    p.add_argument('--registration-file', type=Path, required=True)
    p.add_argument('--expected'); p.add_argument('--root'); p.add_argument('--state-dir')
    p.add_argument('--owned-pid', type=int); p.add_argument('--owner-pid', type=int)
    a = p.parse_args(argv)
    checkpoint('START')
    try:
        if a.owner_pid is not None: need(a.owner_pid == os.getppid(), 'MONITOR_INVALID')
        result = resolve(a.registration_file, a.action, expected=a.expected, root=a.root, state=a.state_dir,
                         owned_pid=a.owned_pid, owner_pid=a.owner_pid)
    except Hold as error:
        code = str(error); result = {'status': 'HOLD', 'reason': code, 'message': MESSAGES.get(code, MESSAGES['IO_ERROR'])}
    except (OSError, ValueError, KeyError, TypeError):
        result = {'status': 'HOLD', 'reason': 'IO_ERROR', 'message': MESSAGES['IO_ERROR']}
    checkpoint('DONE')
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == '__main__': raise SystemExit(main())
