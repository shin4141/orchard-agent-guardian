"""Read-only bounded provider. No acquisition/scheduler/publication entry."""
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import warehouse as baseline
from feed_adapter import SuppressionLedger
from threat_db import HASH_TABLE, revocation_tag, utc_timestamp
HERE = Path(__file__).absolute().parent
Warehouse = baseline.Warehouse
WarehouseProvider = baseline.WarehouseProvider
WarehouseError = baseline.WarehouseError
private_read = baseline.private_read
stamp = baseline.stamp
PERMISSION = baseline.PERMISSION
APPLICATION_ID = baseline.APPLICATION_ID
NEGATIVE_MAX_AGE_SECONDS = baseline.NEGATIVE_MAX_AGE_SECONDS
MAX_DB_BYTES = baseline.MAX_DB_BYTES
inspect_zip = baseline.inspect_zip
class Hold(ValueError):
    """Stable codes only. Never attach source values or transport exceptions."""

def require(ok, code):
    if not ok:
        raise Hold(code)

def sha(data):
    return hashlib.sha256(data).hexdigest()
REAL = 'MALWAREBAZAAR_REAL_SHA_BOUNDED_SUBSET'
SYNTHETIC = 'SYNTHETIC_BOUNDED_SUBSET_FIXTURE'
SCHEMA = 'orchard-bounded-sha-warehouse/1'
DOMAIN = b'Orchard bounded subset v1\x00'
LEGACY_TEXT = 'MALWAREBAZAAR_FULL_SHA256_TEXT_V1'
STRUCTURAL_TEXT = 'MALWAREBAZAAR_FULL_SHA256_STRUCTURAL_TEXT_V1'
_ORIGIN = 'https://mb-api.abuse.ch'
_FILE = 'sha256_full.txt.zip'

def policy():
    return json.loads((HERE / 'POLICY.json').read_bytes())

def policy_hash(limits):
    return hashlib.sha256(json.dumps(limits, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def validate_manifest_source(full, kind):
    """Persisted claims must preserve the synthetic/official distinction."""
    e = full.get('source_binding', {})
    official = kind == REAL
    require(e.get('schema') == 'orchard-full-source-binding/1' and e.get('official_source_authenticated') is official and (e.get('source_kind') == ('OFFICIAL_HTTPS' if official else 'SYNTHETIC_TRANSPORT_DOUBLE')) and (e.get('origin') == (_ORIGIN if official else None)) and (e.get('file') == _FILE) and (e.get('authentication_basis') == ('SAME_PROCESS_FIXED_HOST_DEFAULT_TLS_ONE_SHOT_TRANSPORT' if official else 'SYNTHETIC_ONLY_NO_AUTHENTICATION_CLAIM')) and (e.get('json_receipt_can_activate') is False) and (e.get('host_principal_isolation_claimed') is False) and (e.get('retrieved_at_utc') == full['retrieved_at_utc']) and (e.get('archive_sha256') == full.get('archive_sha256')) and (type(e.get('archive_sha256')) is str) and (re.fullmatch('[0-9a-f]{64}', e['archive_sha256']) is not None) and (e.get('policy_sha256') == policy_hash(policy())) and (full.get('title_role') == 'BOUNDED_INFORMATIONAL_NOT_SOURCE_AUTHENTICATION') and (full.get('zip_entire_container_pass') is True) and (full.get('complete_deflate_stream_pass') is True), 'SOURCE_PROFILE')

def validate_metadata(m, ledger):
    require(m['schema'] == SCHEMA and m['data_kind'] in {REAL, SYNTHETIC}, 'CANDIDATE_PROFILE')
    require(m['retained_sample_fields'] == ['sha256'] and m['automatic_updates'] is False and (m['public_gate'] == 'HOLD') and (m['permission_original_sha256'] == PERMISSION), 'CANDIDATE_BOUNDARY')
    require(m['suppression_ledger_sha256'] == ledger.sha256 and m['suppression_revision'] == ledger.revision and (not ledger.withdrawn), 'SUPPRESSION_IDENTITY')
    require(m['negative_max_age_seconds'] == NEGATIVE_MAX_AGE_SECONDS and m['source']['selection_domain_hex'] == DOMAIN.hex() and (m['source']['full']['profile'] in {LEGACY_TEXT, STRUCTURAL_TEXT}) and (m['source']['full']['zip_crc32_pass'] is True), 'SOURCE_PROFILE')
    if m['source']['full']['profile'] == STRUCTURAL_TEXT:
        validate_manifest_source(m['source']['full'], m['data_kind'])
    if m['data_kind'] == REAL:
        source = m['source']
        counts = m['counts']
        retained = source.get('retained_snapshot', {})
        require(source.get('expansion_profile') == 'RETAIN_100K_DAILY_EXPAND_TO_300K_V1' and retained.get('database_sha256') == 'c6ae23abcddcab9176a12514a11d4d0a094dfe4894e494fbf9a33d5fc4b4a2ff' and (retained.get('retained_rows') == counts.get('old_retained_unique') == 100000) and (counts.get('selected_unique') == m['total_unique_rows']) and (counts.get('new_added_unique') == m['total_unique_rows'] - 100000) and (counts.get('recent_added_unique') + counts.get('full_added_unique') == counts.get('new_added_unique')) and (100000 <= m['total_unique_rows'] <= 300000), 'EXPANSION_PROFILE_OR_COUNTS')
    full, recent, source = (m['source']['full'], m['source']['recent'], m['source'])
    require(source['source_generated_at_utc'] == min(full['source_generated_at_utc'], recent['source_generated_at_utc'], source.get('retained_snapshot', recent)['source_generated_at_utc']) and source['retrieved_at_utc'] == min(full['retrieved_at_utc'], recent['retrieved_at_utc'], source.get('retained_snapshot', recent)['retrieved_at_utc']), 'SOURCE_AGE_RESET')
    for part in (full, recent, source.get('retained_snapshot', recent)):
        require(utc_timestamp(part['source_generated_at_utc']) <= utc_timestamp(part['retrieved_at_utc']), 'SOURCE_TIME')

class BoundedStore(Warehouse):

    def _load(self):
        if (self.root / 'withdrawal.json').exists():
            raise Hold('PERMISSION_WITHDRAWN')
        pointer = self.root / 'current.json'
        if not pointer.exists() and (not pointer.is_symlink()):
            return None
        con = None
        try:
            pb = private_read(pointer, 1024)
            active = json.loads(pb)
            require(set(active) == {'schema', 'generation', 'manifest_sha256'} and active['schema'] == 'orchard-bounded-active/1' and re.fullmatch('g-[0-9a-f]{32}', active['generation']), 'POINTER_PROFILE')
            root = self.root / active['generation']
            mb = private_read(root / 'manifest.json', 131072)
            require(sha(mb) == active['manifest_sha256'], 'MANIFEST_CHECKSUM')
            m = json.loads(mb)
            ledger = SuppressionLedger.from_dict(json.loads(private_read(root / 'suppression.json', 16 * 1024 * 1024)))
            validate_metadata(m, ledger)
            data = private_read(root / 'hashes.sqlite3', policy()['database_bytes_cap'])
            require(sha(data) == m['database_sha256'] and len(data) == m['database_bytes'], 'DB_CHECKSUM')
            con = sqlite3.connect(':memory:')
            con.deserialize(data)
            con.execute('PRAGMA trusted_schema=OFF')
            con.execute('PRAGMA query_only=ON')
            require(con.execute('PRAGMA application_id').fetchone() == (APPLICATION_ID,) and con.execute('PRAGMA user_version').fetchone() == (1,) and (con.execute('SELECT name,type FROM sqlite_schema').fetchall() == [('hashes', 'table')]) and (con.execute("SELECT sql FROM sqlite_schema WHERE name='hashes'").fetchone() == (HASH_TABLE,)) and (con.execute('PRAGMA integrity_check').fetchone() == ('ok',)), 'DB_SCHEMA_OR_INTEGRITY')
            count = 0
            for digest, in con.execute('SELECT sha256 FROM hashes'):
                require(type(digest) is bytes and len(digest) == 32 and (not ledger.tokens or revocation_tag(digest) not in ledger.tokens), 'DB_ROW_OR_SUPPRESSION')
                count += 1
            require(count == m['total_unique_rows'] and 0 <= count <= 300000, 'DB_COUNT')
            require(private_read(pointer, 1024) == pb, 'CURRENT_CHANGED')
            return {'active': active, 'pin': sha(pb), 'manifest': m, 'ledger': ledger, 'con': con}
        except Exception:
            if con is not None:
                con.close()
            raise Hold('CANDIDATE_VALIDATION_FAILED') from None

class BoundedProvider(WarehouseProvider):

    def describe(self):
        self._current()
        m = self.state['manifest']
        source = m['source']
        now = self.clock()
        times = [utc_timestamp(source[x]) for x in ('source_generated_at_utc', 'retrieved_at_utc')]
        reason = 'DB_CLOCK_INVALID' if now < max(times) else 'DB_STALE' if now - min(times) > NEGATIVE_MAX_AGE_SECONDS else 'DB_READY'
        attempt = self.store.root / 'failed-attempt.json'
        if attempt.exists():
            reason = 'UPDATE_FAILED'
        return {'status': 'READY' if reason == 'DB_READY' else 'DB_NOT_UPDATED', 'reason': reason, 'max_age_seconds': NEGATIVE_MAX_AGE_SECONDS, 'age_seconds': round(now - min(times), 3), 'snapshot_sha256': m['database_sha256'], 'automatic_updates': False, 'metadata': {'data_kind': m['data_kind'], 'record_count': m['total_unique_rows'], 'provider': 'abuse.ch-malwarebazaar' if m['data_kind'] == REAL else 'synthetic-fixture', 'coverage': m['coverage'], 'attribution': m['attribution'], 'fields': ['sha256']}, 'safety_proven': False, 'authorizes_actions': False}

MAX_DB_BYTES = policy()['database_bytes_cap']
