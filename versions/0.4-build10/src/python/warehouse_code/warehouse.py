"""Private immutable SHA warehouse; no network, scheduler, payloads or hash logs.

Real and synthetic stores have distinct identities. Existing app/pilot profiles
and their two-hour TTL are unchanged. This provider has an explicit daily policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import uuid

TI = Path(__file__).resolve().parents[1]
if str(TI) not in sys.path:
    sys.path.insert(0, str(TI))
from feed_adapter import FormatProfile, SuppressionLedger, TransferReceipt, _Reader, _parse
from threat_db import HASH_TABLE, _read_regular, revocation_tag, sha_bytes, utc_timestamp

REAL = "MALWAREBAZAAR_REAL_SHA_WAREHOUSE"
SYNTHETIC = "SYNTHETIC_WAREHOUSE_FIXTURE"
KINDS = {REAL, SYNTHETIC}
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILE_ROWS = MAX_WAREHOUSE_ROWS = 100_000
MAX_DB_BYTES = 16 * 1024 * 1024
DAILY_SECONDS = 86400
NEGATIVE_MAX_AGE_SECONDS = 90000  # one day + one hour, separately qualified
APPLICATION_ID = 0x4F574831
PERMISSION = "4381705ad2401cda8e7cd09bc5f94d6964771ee9601ffeae5031851b29409d8f"
PROFILE = "MALWAREBAZAAR_RECENT_SHA256_TEXT_20261114_V1"


class WarehouseError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def private_read(path, cap):
    path = Path(path)
    if any(p.is_symlink() for p in path.parents):
        raise WarehouseError("SYMLINK_PARENT_REJECTED")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise WarehouseError("PRIVATE_FILE_REQUIRED")
    return _read_regular(path, cap)


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def atomic_json(path, value):
    temporary = path.parent / (".json-" + uuid.uuid4().hex)
    try:
        private_write(temporary, json_bytes(value))
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class Publication:
    kind: str
    source: dict
    records: tuple[bytes, ...] = field(repr=False)


def parse_publication(body, receipt, *, kind, ledger, now):
    """Qualify the observed nine-line header, SHA-only data and count footer.

    SHA rows never enter exceptions or repr. Footer count is provider-declared;
    the local checksum identifies received bytes, not a provider signature.
    """
    ledger.validate()
    if kind not in KINDS:
        raise WarehouseError("DATA_KIND_INVALID")
    meta = receipt.get("metadata", {})
    expected_transport = "OFFICIAL_HTTPS" if kind == REAL else "SYNTHETIC_TRANSPORT_DOUBLE"
    if (receipt.get("result") != "PASS_COMPLETE_FILE_TRANSFER_NOT_YET_INGESTED"
            or meta.get("source_kind") != expected_transport or meta.get("complete") is not True
            or meta.get("file") != "sha256_recent.txt" or meta.get("http_status") != 200
            or meta.get("origin") != "https://mb-api.abuse.ch"
            or meta.get("content_type") != "text/plain" or meta.get("content_encoding") != "identity"
            or meta.get("completion_basis") != "HTTPS_CONTENT_LENGTH_FULL_BODY"):
        raise WarehouseError("SOURCE_KIND_OR_TRANSFER_NOT_QUALIFIED")
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_FILE_BYTES:
        raise WarehouseError("FILE_BYTE_CAP_OR_TYPE")
    if (len(body) != meta.get("content_length") or len(body) != meta.get("received_bytes")
            or checksum(body) != receipt.get("body_sha256") or not body.endswith(b"\n")):
        raise WarehouseError("FILE_LENGTH_CHECKSUM_OR_TERMINATION")
    try:
        lines = body[:-1].split(b"\n")
        if any(len(x) > 4096 for x in lines):
            raise WarehouseError("LINE_LENGTH_LIMIT")
        text = [x[:-1].decode("ascii") if x.endswith(b"\r") else x.decode("ascii") for x in lines]
        if len(text) < 10 or any(any(ord(c) < 32 or ord(c) > 126 for c in x) for x in text):
            raise WarehouseError("ASCII_FILE_GRAMMAR_REQUIRED")
        if text[0] != "#" * 64 or text[6] != "#" * 64 or text[7:9] != ["#", "# sha256_hash"]:
            raise WarehouseError("OFFICIAL_HEADER_PROFILE_MISMATCH")
        labels = [x[1:].rstrip(" #").strip() if x.startswith("#") else None for x in text[1:6]]
        if (labels[0] != "MalwareBazaar recent malware samples (SHA256 hashes)" or labels[2] != ""
                or labels[3] != "Terms Of Use: https://bazaar.abuse.ch/faq/#tos"
                or labels[4] != "For questions please contact bazaar [at] abuse.ch"):
            raise WarehouseError("OFFICIAL_HEADER_PROFILE_MISMATCH")
        generation = re.fullmatch(r"Last updated: (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) UTC", labels[1] or "")
        footer = re.fullmatch(r"# Number of entries: ([0-9]{1,6})", text[-1])
        if generation is None or footer is None:
            raise WarehouseError("PUBLISHER_TIME_OR_FOOTER_MISSING")
        count = int(footer[1])
        if not 0 < count <= MAX_FILE_ROWS or len(text) - 10 != count:
            raise WarehouseError("PROVIDER_COUNT_MISMATCH_OR_CAP")
        generated = generation[1] + "T" + generation[2] + "Z"
        retrieved = receipt["retrieved_at_utc"]
        gt, rt = utc_timestamp(generated), utc_timestamp(retrieved)
        if gt > rt or rt > now or now - rt > NEGATIVE_MAX_AGE_SECONDS or now - gt > NEGATIVE_MAX_AGE_SECONDS:
            raise WarehouseError("SOURCE_OR_RETRIEVAL_FUTURE_OR_TOO_OLD")
        projection = ("\n".join(text[9:-1]) + "\n").encode("ascii")
        transfer = TransferReceipt(len(projection), checksum(projection), count, True)
        transfer.validate()
        stats = {"records_seen": 0, "accepted_rows": 0, "suppressed_rows": 0}
        reader = _Reader(io.BytesIO(projection), transfer, time.monotonic() + 30)
        records = tuple(_parse(reader, FormatProfile(PROFILE, "text", allow_bom=False), ledger, stats))
        unique = tuple(sorted(set(records)))
        source = {"data_kind": kind, "format_profile": PROFILE, "source_documentation": "https://bazaar.abuse.ch/export/",
                  "dataset": "recent", "file": "sha256_recent.txt", "retrieved_at_utc": retrieved,
                  "source_generated_at_utc": generated, "source_time_basis": "PROVIDER_FILE_LAST_UPDATED_PREAMBLE",
                  "HTTP_date_utc": meta.get("HTTP_date_utc"), "HTTP_last_modified_utc": meta.get("HTTP_last_modified_utc"),
                  "declared_coverage_start_utc": stamp(gt - 48 * 3600), "declared_coverage_end_utc": generated,
                  "coverage_basis": "PROVIDER_DECLARED_RECENT_48H_NOT_OBSERVED_MEMBER_FIRST_SEEN",
                  "provider_declared_rows": count, "parsed_rows": stats["records_seen"],
                  "suppressed_rows": stats["suppressed_rows"], "unique_accepted_rows": len(unique),
                  "duplicate_accepted_rows": stats["accepted_rows"] - len(unique),
                  "source_bytes": len(body), "source_file_sha256": checksum(body),
                  "normalized_projection_sha256": checksum(projection), "provider_checksum": None,
                  "transport_completion": meta["completion_basis"], "permission_original_sha256": PERMISSION}
        return Publication(kind, source, unique)
    except WarehouseError:
        raise
    except Exception:
        raise WarehouseError("FILE_PROFILE_OR_PARSE_REJECTED") from None


class Warehouse:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if self.root.is_symlink() or any(p.is_symlink() for p in self.root.parents):
            raise WarehouseError("STORE_SYMLINK_REJECTED")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise WarehouseError("STORE_NOT_PRIVATE")

    def _lock(self):
        fd = os.open(self.root / "writer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise WarehouseError("WRITER_LOCK_IDENTITY_INVALID")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except Exception:
            os.close(fd)
            raise WarehouseError("WRITER_LOCK_UNAVAILABLE") from None

    def _load(self):
        if (self.root / "withdrawal.json").exists():
            raise WarehouseError("PERMISSION_WITHDRAWN")
        path = self.root / "current.json"
        if not path.exists() and not path.is_symlink():
            return None
        con = None
        try:
            active_bytes = private_read(path, 1024)
            active = json.loads(active_bytes)
            if (set(active) != {"schema", "generation", "manifest_sha256"} or active["schema"] != "orchard-warehouse-active/1"
                    or not re.fullmatch(r"g-[0-9a-f]{32}", active["generation"])):
                raise WarehouseError("ACTIVE_POINTER_INVALID")
            generation = self.root / active["generation"]
            data = private_read(generation / "manifest.json", 128 * 1024)
            if checksum(data) != active["manifest_sha256"]:
                raise WarehouseError("MANIFEST_CHECKSUM_MISMATCH")
            manifest = json.loads(data)
            if (manifest["schema"] != "orchard-sha-warehouse/1" or manifest["data_kind"] not in KINDS
                    or manifest["retained_sample_fields"] != ["sha256"] or manifest["automatic_updates"] is not False
                    or manifest["permission_original_sha256"] != PERMISSION
                    or manifest["source"]["permission_original_sha256"] != PERMISSION
                    or manifest["source"]["data_kind"] != manifest["data_kind"]
                    or manifest["source"]["format_profile"] != PROFILE
                    or manifest["source"]["file"] != "sha256_recent.txt"):
                raise WarehouseError("MANIFEST_PROFILE_INVALID")
            ledger = SuppressionLedger.from_dict(json.loads(private_read(generation / "suppression.json", 16 * 1024 * 1024)))
            if ledger.sha256 != manifest["suppression_ledger_sha256"] or ledger.withdrawn:
                raise WarehouseError("SUPPRESSION_IDENTITY_INVALID")
            db = private_read(generation / "hashes.sqlite3", MAX_DB_BYTES)
            if checksum(db) != manifest["database_sha256"] or len(db) != manifest["database_bytes"]:
                raise WarehouseError("DATABASE_CHECKSUM_MISMATCH")
            con = sqlite3.connect(":memory:")
            con.deserialize(db)
            con.execute("PRAGMA trusted_schema=OFF")
            con.execute("PRAGMA query_only=ON")
            if (con.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                    or con.execute("PRAGMA user_version").fetchone()[0] != 1
                    or con.execute("SELECT name,type FROM sqlite_schema").fetchall() != [("hashes", "table")]
                    or con.execute("SELECT sql FROM sqlite_schema WHERE name='hashes'").fetchone()[0] != HASH_TABLE
                    or con.execute("PRAGMA integrity_check").fetchone() != ("ok",)):
                raise WarehouseError("DATABASE_SCHEMA_OR_INTEGRITY_INVALID")
            count = con.execute("SELECT count(*) FROM hashes").fetchone()[0]
            if count != manifest["total_unique_rows"] or not 0 <= count <= MAX_WAREHOUSE_ROWS:
                raise WarehouseError("DATABASE_ROW_COUNT_INVALID")
            if private_read(path, 1024) != active_bytes:
                raise WarehouseError("CURRENT_CHANGED")
            return {"active": active, "pin": checksum(active_bytes), "manifest": manifest, "ledger": ledger, "con": con}
        except WarehouseError:
            if con is not None:
                con.close()
            raise
        except Exception:
            if con is not None:
                con.close()
            raise WarehouseError("CURRENT_STORE_VALIDATION_FAILED") from None

    def _publish(self, records, *, kind, ledger, source, previous, stats, now, maintenance=False):
        if len(records) > MAX_WAREHOUSE_ROWS:
            raise WarehouseError("WAREHOUSE_TOTAL_CAP_HOLD_NO_TRUNCATION")
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=self.root))
        generation = "g-" + uuid.uuid4().hex
        published = False
        try:
            db = stage / "hashes.sqlite3"
            con = sqlite3.connect(db)
            try:
                con.execute("PRAGMA journal_mode=DELETE")
                con.execute("PRAGMA synchronous=FULL")
                con.execute(f"PRAGMA application_id={APPLICATION_ID}")
                con.execute("PRAGMA user_version=1")
                con.execute(HASH_TABLE)
                with con:
                    con.executemany("INSERT INTO hashes VALUES (?)", ((x,) for x in sorted(records)))
                if con.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                    raise WarehouseError("NEW_DATABASE_INTEGRITY_FAILED")
            finally:
                con.close()
            db.chmod(0o600)
            data = private_read(db, MAX_DB_BYTES)
            old = previous["manifest"] if previous else None
            gap = (old is not None and utc_timestamp(source["source_generated_at_utc"]) - utc_timestamp(old["source"]["source_generated_at_utc"]) > 48 * 3600)
            manifest = {"schema": "orchard-sha-warehouse/1", "data_kind": kind,
                "database_sha256": checksum(data), "database_bytes": len(data), "total_unique_rows": len(records),
                "retained_sample_fields": ["sha256"], "suppression_ledger_sha256": ledger.sha256,
                "suppression_revision": ledger.revision, "source": source, "counts": stats,
                "first_admitted_source_utc": old["first_admitted_source_utc"] if old else source["source_generated_at_utc"],
                "coverage_gap_observed": bool(gap or old and old["coverage_gap_observed"]),
                "coverage": "UNION_OF_ADMITTED_RECENT_FILES_NOT_FULL_CORPUS; absence from a later 48h file is not revocation",
                "last_maintenance_at_utc": stamp(now) if maintenance else None,
                "update_interval_seconds": DAILY_SECONDS, "negative_max_age_seconds": NEGATIVE_MAX_AGE_SECONDS,
                "automatic_updates": False, "permission_ticket": "ST7343382", "permission_original_sha256": PERMISSION,
                "attribution": "Malware hash data courtesy of abuse.ch MalwareBazaar (https://bazaar.abuse.ch), provided in collaboration with Spamhaus Technology. Used with permission. No match does not mean a file is safe." if kind == REAL else "Synthetic fixture only; no real SHA acquisition"}
            private_write(stage / "suppression.json", json_bytes(ledger.as_dict()))
            manifest_bytes = json_bytes(manifest)
            private_write(stage / "manifest.json", manifest_bytes)
            os.rename(stage, self.root / generation)
            atomic_json(self.root / "current.json", {"schema": "orchard-warehouse-active/1", "generation": generation,
                                                       "manifest_sha256": checksum(manifest_bytes)})
            published = True
            if previous:
                previous["con"].close()
                shutil.rmtree(self.root / previous["active"]["generation"])
            if not maintenance:
                atomic_json(self.root / "attempt.json", {"checked_at_utc": source["retrieved_at_utc"], "status": "SUCCESS"})
            return manifest
        finally:
            if stage.exists():
                shutil.rmtree(stage)
            if not published and (self.root / generation).exists():
                shutil.rmtree(self.root / generation)

    def apply(self, body, receipt, *, kind, ledger, now=None):
        now = time.time() if now is None else now
        fd = self._lock()
        previous = None
        try:
            previous = self._load()
            ledger.require_successor(previous["ledger"] if previous else None)
            publication = parse_publication(body, receipt, kind=kind, ledger=ledger, now=now)
            source = publication.source
            old_records = set()
            if previous:
                old = previous["manifest"]
                if old["data_kind"] != kind:
                    raise WarehouseError("REAL_SYNTHETIC_STORE_MIXING_REJECTED")
                prior = old["source"]
                if source == prior and ledger.sha256 == previous["ledger"].sha256:
                    return {**old, "operation_result": "ALREADY_APPLIED_NO_CHANGE"}
                if (utc_timestamp(source["source_generated_at_utc"]) < utc_timestamp(prior["source_generated_at_utc"])
                        or utc_timestamp(source["retrieved_at_utc"]) < utc_timestamp(prior["retrieved_at_utc"])):
                    raise WarehouseError("SOURCE_OR_RETRIEVAL_ROLLBACK")
                if (source["source_generated_at_utc"] == prior["source_generated_at_utc"]
                        and source["source_file_sha256"] != prior["source_file_sha256"]):
                    raise WarehouseError("SOURCE_TIME_REUSED_WITH_DIFFERENT_BYTES")
                if utc_timestamp(source["retrieved_at_utc"]) - utc_timestamp(prior["retrieved_at_utc"]) < DAILY_SECONDS:
                    raise WarehouseError("DAILY_UPDATE_NOT_DUE_NO_FREQUENCY_INCREASE")
                old_records = {row[0] for row in previous["con"].execute("SELECT sha256 FROM hashes")}
            kept = {x for x in old_records if revocation_tag(x) not in ledger.tokens}
            incoming = set(publication.records)
            stats = {"source_rows": source["parsed_rows"], "source_unique_accepted": len(incoming),
                     "source_duplicate_accepted_rows": source["duplicate_accepted_rows"],
                     "source_suppressed_rows": source["suppressed_rows"], "previous_unique_rows": len(old_records),
                     "removed_previous_rows": len(old_records) - len(kept), "overlap_with_previous": len(incoming & kept),
                     "added_unique_rows": len(incoming - kept)}
            return self._publish(kept | incoming, kind=kind, ledger=ledger, source=source, previous=previous, stats=stats, now=now)
        except Exception:
            if (self.root / "current.json").exists():
                atomic_json(self.root / "attempt.json", {"checked_at_utc": stamp(now), "status": "FAILED"})
            raise
        finally:
            if previous:
                previous["con"].close()
            os.close(fd)

    def suppress(self, ledger, *, now=None):
        now = time.time() if now is None else now
        fd = self._lock()
        previous = None
        try:
            previous = self._load()
            if previous is None:
                raise WarehouseError("NO_CURRENT_WAREHOUSE")
            ledger.require_successor(previous["ledger"])
            records = {r[0] for r in previous["con"].execute("SELECT sha256 FROM hashes")}
            kept = {x for x in records if revocation_tag(x) not in ledger.tokens}
            return self._publish(kept, kind=previous["manifest"]["data_kind"], ledger=ledger,
                source=previous["manifest"]["source"], previous=previous, now=now, maintenance=True,
                stats={"removed_previous_rows": len(records) - len(kept), "source_rows": 0, "added_unique_rows": 0})
        finally:
            if previous:
                previous["con"].close()
            os.close(fd)

    def withdraw(self, ledger):
        fd = self._lock()
        previous = None
        try:
            previous = self._load()
            ledger.validate()
            if previous is None or not ledger.withdrawn:
                raise WarehouseError("EXPLICIT_WITHDRAWN_SUCCESSOR_REQUIRED")
            compatible = SuppressionLedger(ledger.revision, ledger.tokens, False, ledger.request_refs)
            compatible.require_successor(previous["ledger"])
            atomic_json(self.root / "withdrawal.json", ledger.as_dict())  # block readers first
            previous["con"].close()
            (self.root / "current.json").unlink()
            retired = 0
            for path in self.root.iterdir():
                if re.fullmatch(r"g-[0-9a-f]{32}", path.name):
                    if path.is_symlink():
                        raise WarehouseError("GENERATION_SYMLINK_REJECTED")
                    shutil.rmtree(path)
                    retired += 1
            return {"result": "WITHDRAWN_LOCAL_GENERATIONS_RETIRED", "generations_retired": retired}
        finally:
            if previous:
                previous["con"].close()
            os.close(fd)


class WarehouseProvider:
    """Checksum-verified, query-only memory copy, pinned to current at each use."""
    def __init__(self, store, *, now=None):
        self.store = store if isinstance(store, Warehouse) else Warehouse(store)
        self.clock = time.time if now is None else lambda: now
        self.state = self.store._load()
        if self.state is None:
            raise WarehouseError("NO_CURRENT_WAREHOUSE")

    def _current(self):
        if ((self.store.root / "withdrawal.json").exists()
                or checksum(private_read(self.store.root / "current.json", 1024)) != self.state["pin"]):
            raise WarehouseError("CURRENT_CHANGED_OR_WITHDRAWN")

    def describe(self):
        self._current()
        m = self.state["manifest"]
        source = m["source"]
        now = self.clock()
        generated, retrieved = utc_timestamp(source["source_generated_at_utc"]), utc_timestamp(source["retrieved_at_utc"])
        future = now < max(generated, retrieved)
        old = now - min(generated, retrieved) > NEGATIVE_MAX_AGE_SECONDS
        attempt = json.loads(private_read(self.store.root / "attempt.json", 1024))
        failed = attempt.get("status") != "SUCCESS"
        reason = "DB_CLOCK_INVALID" if future else "UPDATE_FAILED" if failed else "DB_STALE" if old else "DB_READY"
        return {"status": "READY" if reason == "DB_READY" else "DB_NOT_UPDATED", "reason": reason,
                "age_seconds": round(now - generated, 3), "max_age_seconds": NEGATIVE_MAX_AGE_SECONDS,
                "next_check_due_utc": stamp(retrieved + DAILY_SECONDS), "update_due": now >= retrieved + DAILY_SECONDS,
                "snapshot_sha256": m["database_sha256"], "metadata": {"provider": "abuse.ch-malwarebazaar" if m["data_kind"] == REAL else "synthetic-fixture",
                "data_kind": m["data_kind"], "record_count": m["total_unique_rows"], "updated_at_utc": source["source_generated_at_utc"],
                "coverage": m["coverage"], "coverage_gap_observed": m["coverage_gap_observed"], "fields": ["sha256"],
                "attribution": m["attribution"]}, "automatic_updates": False, "safety_proven": False, "authorizes_actions": False}

    def lookup(self, digest):
        self._current()
        value = sha_bytes(digest)
        matched = self.state["con"].execute("SELECT 1 FROM hashes WHERE sha256=?", (value,)).fetchone() is not None
        self._current()
        return matched

    def classify(self, digest):
        description = self.describe()
        matched = self.lookup(digest)
        hit_message = "収録済みSHAに一致しました。"
        if description["status"] != "READY":
            hit_message += "DBは更新未確認です。"
        hit_message += "安全性や実行許可の判定ではありません。"
        return {"status": "KNOWN_HASH_MATCH" if matched else "NO_MATCH_IN_COVERED_DB" if description["status"] == "READY" else "DB_NOT_UPDATED",
                "database": description, "message_ja": hit_message if matched
                else "この限定的な倉庫内に一致はありません。安全を意味しません。" if description["status"] == "READY"
                else "DBの更新を確認できないため、不一致を判定できません。",
                "safety_proven": False, "authorizes_actions": False}

    def close(self):
        if self.state:
            self.state["con"].close()
            self.state = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def update_plan(store, *, now=None):
    with WarehouseProvider(store, now=now) as provider:
        status = provider.describe()
        return {"automatic_execution_enabled": False, "operator_authorized_once_required": True,
                "intended_interval_seconds": DAILY_SECONDS, "update_due": status["update_due"],
                "next_check_due_utc": status["next_check_due_utc"], "negative_max_age_seconds": NEGATIVE_MAX_AGE_SECONDS,
                "current_database_state": status["status"], "file_cap": 1, "per_file_byte_cap": MAX_FILE_BYTES,
                "per_file_row_cap": MAX_FILE_ROWS, "total_warehouse_row_cap": MAX_WAREHOUSE_ROWS,
                "catch_up_rule": "Never invent a missing interval or silently fetch extra files; a gap over 48h remains disclosed"}


def inspect_zip(source, provider):
    """Keep R1 evidence/gates and correct only the new profile's display labels."""
    from inspection import inspect_zip as original_inspect
    result = original_inspect(source, provider)
    ti = result["threat_intelligence"]
    if provider.state["manifest"]["data_kind"] == REAL:
        ti["limitations"] = ti["limitations"][:2] + ["Limited real SHA warehouse of admitted Recent files; not the full MalwareBazaar corpus."]
        if ti["status"] == "KNOWN_HASH_MATCH":
            ti["message_ja"] = "限定的な実SHA倉庫の収録SHAに一致。" + ("DBは更新未確認です。" if ti["database"]["status"] != "READY" else "") + "安全性は判定しません。"
    return result
