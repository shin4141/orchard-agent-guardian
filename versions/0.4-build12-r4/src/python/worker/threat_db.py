"""Removable offline SHA providers, with explicit synthetic and real-pilot gates."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from typing import Iterable, Protocol


SCHEMA = "orchard-ti-snapshot/1"
DATA_KIND = "SYNTHETIC_ONLY"
MAX_DB_BYTES = 256 * 1024 * 1024
MAX_AGE_SECONDS = 7200
APPLICATION_ID = 0x4F544931
HASH_TABLE = "CREATE TABLE hashes (sha256 BLOB PRIMARY KEY NOT NULL CHECK(length(sha256)=32)) WITHOUT ROWID"
META_TABLE = "CREATE TABLE metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL) WITHOUT ROWID"
MANIFEST_KEYS = {"schema", "data_kind", "db_file", "db_sha256", "db_bytes", "metadata"}
META_KEYS = {"provider", "source_url", "data_kind", "updated_at_utc", "coverage", "fields", "record_count", "attribution", "license_basis", "deletion_revision"}
HEX = re.compile(r"[0-9a-fA-F]{64}\Z")


@dataclass(frozen=True)
class SnapshotProfile:
    data_kind: str
    provider: str
    source_url: str
    coverage: str
    attribution: str
    license_basis: str
    max_records: int


SYNTHETIC_PROFILE = SnapshotProfile(DATA_KIND, "synthetic-fixture",
    "urn:orchard:synthetic:ti-integration-01", "synthetic-fixture-only",
    "Synthetic fixture; no abuse.ch data included", "SYNTHETIC_TEST_FIXTURE", 3_000_000)
REAL_PILOT_PROFILE = SnapshotProfile("MALWAREBAZAAR_REAL_SHA_PILOT", "abuse.ch-malwarebazaar",
    "https://bazaar.abuse.ch/api/", "authenticated-latest-100-additions-only-not-full-corpus",
    "Malware hash data courtesy of abuse.ch MalwareBazaar (https://bazaar.abuse.ch), provided in collaboration with Spamhaus Technology. Used with permission. No match does not mean a file is safe.",
    "ST7343382_FREE_OSS_NO_REVENUE_INITIAL_REAL_SHA_PILOT_GO_PUBLIC_HOLD", 100_000)


def sha_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes) and len(value) == 32:
        return value
    if isinstance(value, str) and HEX.fullmatch(value):
        return bytes.fromhex(value)
    raise ValueError("SHA256_MUST_BE_EXACTLY_32_BYTES_OR_64_HEX")


def utc_timestamp(value: str) -> float:
    import datetime
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("UTC_TIMESTAMP_REQUIRED")
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()


def utc_now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_regular(path: Path, cap: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cap:
            raise ValueError("UNSUPPORTED_OR_OVERSIZED_FILE")
        data = handle.read(cap + 1)
        after = os.fstat(handle.fileno())
        if len(data) > cap or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("FILE_CHANGED_OR_LIMIT")
        return data


def _validate_metadata(metadata: dict, profile: SnapshotProfile = SYNTHETIC_PROFILE) -> None:
    if not isinstance(metadata, dict) or set(metadata) != META_KEYS:
        raise ValueError("METADATA_ALLOWLIST_MISMATCH")
    # No API credential, free text, sample names, tags or malware payload column.
    if profile not in (SYNTHETIC_PROFILE, REAL_PILOT_PROFILE):
        raise ValueError("SNAPSHOT_PROFILE_NOT_APPROVED")
    if metadata["provider"] != profile.provider or metadata["data_kind"] != profile.data_kind or metadata["source_url"] != profile.source_url:
        raise ValueError("PROFILE_OR_REAL_DATA_GATE_MISMATCH")
    if metadata["fields"] != ["sha256"] or metadata["coverage"] != profile.coverage:
        raise ValueError("UNAPPROVED_DATA_FIELDS")
    if metadata["attribution"] != profile.attribution or metadata["license_basis"] != profile.license_basis:
        raise ValueError("LICENSE_PROVENANCE_MISMATCH")
    if type(metadata["record_count"]) is not int or not 0 <= metadata["record_count"] <= profile.max_records:
        raise ValueError("INVALID_RECORD_COUNT")
    if type(metadata["deletion_revision"]) is not int or metadata["deletion_revision"] < 0:
        raise ValueError("INVALID_DELETION_REVISION")
    utc_timestamp(metadata["updated_at_utc"])


def revocation_tag(digest: bytes) -> str:
    """Retain a suppression token, not the deleted source SHA or metadata."""
    return hashlib.sha256(b"orchard-ti-suppression/1\0" + sha_bytes(digest)).hexdigest()


def build_synthetic_snapshot(destination: Path, records: Iterable[str | bytes], *, updated_at_utc: str | None = None, suppressed: frozenset[str] = frozenset(), deletion_revision: int = 0) -> Path:
    return _build_snapshot(destination, records, profile=SYNTHETIC_PROFILE, updated_at_utc=updated_at_utc,
                           suppressed=suppressed, deletion_revision=deletion_revision)


def build_real_pilot_snapshot(destination: Path, records: Iterable[str | bytes], *, updated_at_utc: str,
                              suppressed: frozenset[str], deletion_revision: int) -> Path:
    """Explicit initial-pilot entry. Never relabel real rows as synthetic."""
    return _build_snapshot(destination, records, profile=REAL_PILOT_PROFILE, updated_at_utc=updated_at_utc,
                           suppressed=suppressed, deletion_revision=deletion_revision)


def _build_snapshot(destination: Path, records: Iterable[str | bytes], *, profile: SnapshotProfile,
                    updated_at_utc: str | None = None, suppressed: frozenset[str] = frozenset(), deletion_revision: int = 0) -> Path:
    """Create a new complete snapshot. Never modify an installed/in-use DB."""
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError("SNAPSHOT_DESTINATION_MUST_BE_NEW")
    if any(not isinstance(tag, str) or not HEX.fullmatch(tag) for tag in suppressed):
        raise ValueError("INVALID_SUPPRESSION_TOKEN")
    updated = updated_at_utc or utc_now()
    utc_timestamp(updated)
    if type(deletion_revision) is not int or deletion_revision < 0:
        raise ValueError("INVALID_DELETION_REVISION")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".ti-build-", dir=destination.parent))
    try:
        db = staging / "hashes.sqlite3"
        con = sqlite3.connect(db)
        try:
            con.execute("PRAGMA journal_mode=DELETE")
            con.execute("PRAGMA synchronous=FULL")
            con.execute(f"PRAGMA application_id={APPLICATION_ID}")
            con.execute("PRAGMA user_version=1")
            con.execute(HASH_TABLE)
            con.execute(META_TABLE)
            def rows():
                for value in records:
                    digest = sha_bytes(value)
                    if suppressed and revocation_tag(digest) in suppressed:
                        continue
                    yield (digest,)
            with con:
                con.executemany("INSERT OR IGNORE INTO hashes VALUES (?)", rows())
                count = con.execute("SELECT count(*) FROM hashes").fetchone()[0]
                metadata = {
                    "provider": profile.provider, "source_url": profile.source_url,
                    "data_kind": profile.data_kind, "updated_at_utc": updated,
                    "coverage": profile.coverage, "fields": ["sha256"], "record_count": count,
                    "attribution": profile.attribution,
                    "license_basis": profile.license_basis, "deletion_revision": deletion_revision,
                }
                _validate_metadata(metadata, profile)
                con.executemany("INSERT INTO metadata VALUES (?, ?)", ((key, json.dumps(value, ensure_ascii=True)) for key, value in metadata.items()))
            if con.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ValueError("DB_INTEGRITY_FAILED")
        finally:
            con.close()
        db_data = _read_regular(db, MAX_DB_BYTES)
        manifest = {"schema": SCHEMA, "data_kind": profile.data_kind, "db_file": db.name,
                    "db_sha256": hashlib.sha256(db_data).hexdigest(), "db_bytes": len(db_data), "metadata": metadata}
        (staging / "snapshot.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=True) + "\n")
        # Local snapshot creation is separate from acquisition and distribution.
        os.rename(staging, destination)
        return destination / "snapshot.json"
    finally:
        if staging.exists():
            import shutil
            shutil.rmtree(staging)


class ThreatProvider(Protocol):
    def describe(self) -> dict: ...
    def lookup(self, digest: bytes) -> bool: ...


@dataclass
class DisabledProvider:
    reason: str = "PROVIDER_DISABLED"

    def describe(self) -> dict:
        return {"status": "DB_NOT_UPDATED", "reason": self.reason, "metadata": None}

    def lookup(self, digest: bytes) -> bool:
        raise RuntimeError("DB_UNAVAILABLE")


class SQLiteProvider:
    """One pinned read-only DB per inspection; failed validation never means miss."""

    def __init__(self, manifest_path: Path, *, now: float | None = None, profile: SnapshotProfile = SYNTHETIC_PROFILE):
        self.con = None
        self.manifest = None
        self.reason = "DB_INVALID"
        self._now = time.time() if now is None else now
        self.profile = profile
        try:
            manifest_path = Path(manifest_path)
            # Reject symlinks in the selected snapshot path, including parents.
            if any(part.is_symlink() for part in (manifest_path, *manifest_path.parents)):
                raise ValueError("SYMLINK_SNAPSHOT_PATH")
            manifest = json.loads(_read_regular(manifest_path, 16_384))
            if profile not in (SYNTHETIC_PROFILE, REAL_PILOT_PROFILE) or set(manifest) != MANIFEST_KEYS or manifest["schema"] != SCHEMA or manifest["data_kind"] != profile.data_kind or manifest["db_file"] != "hashes.sqlite3":
                raise ValueError("SNAPSHOT_SCHEMA_OR_REAL_DATA_GATE")
            _validate_metadata(manifest["metadata"], profile)
            db = manifest_path.parent / manifest["db_file"]
            data = _read_regular(db, MAX_DB_BYTES)
            if type(manifest["db_bytes"]) is not int or len(data) != manifest["db_bytes"] or hashlib.sha256(data).hexdigest() != manifest["db_sha256"]:
                raise ValueError("DB_IDENTITY_MISMATCH")
            # Deserialize the verified bytes into a private connection. A path
            # replacement, WAL or later write cannot change this inspection.
            con = sqlite3.connect(":memory:", timeout=0.2)
            self.con = con
            con.deserialize(data)
            con.execute("PRAGMA query_only=ON")
            con.execute("PRAGMA trusted_schema=OFF")
            self._query_deadline = time.monotonic() + 2.0
            con.set_progress_handler(lambda: int(time.monotonic() > self._query_deadline), 10_000)
            if con.execute("PRAGMA application_id").fetchone() != (APPLICATION_ID,) or con.execute("PRAGMA user_version").fetchone() != (1,):
                raise ValueError("DB_SCHEMA_VERSION_MISMATCH")
            schema = dict(con.execute("SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
            if schema != {"hashes": HASH_TABLE, "metadata": META_TABLE}:
                raise ValueError("UNAPPROVED_SQL_SCHEMA")
            if con.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("DB_QUICK_CHECK_FAILED")
            metadata = {key: json.loads(value) for key, value in con.execute("SELECT key, value FROM metadata LIMIT 32")}
            if metadata != manifest["metadata"] or con.execute("SELECT count(*) FROM hashes").fetchone()[0] != metadata["record_count"]:
                raise ValueError("DB_METADATA_MISMATCH")
            self.manifest = manifest
            self.reason = "DB_READY"
        except FileNotFoundError:
            self.reason = "DB_MISSING"
            self.close()
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
            self.close()

    def describe(self) -> dict:
        if self.manifest is None or self.con is None:
            return {"status": "DB_NOT_UPDATED", "reason": self.reason, "metadata": None}
        meta = self.manifest["metadata"]
        age = self._now - utc_timestamp(meta["updated_at_utc"])
        # A future timestamp is invalid freshness, not a fresh DB.
        reason = ("DB_EMPTY_COVERAGE" if self.profile == REAL_PILOT_PROFILE and meta["record_count"] == 0 else
                  "DB_CLOCK_INVALID" if age < 0 else "DB_STALE" if age > MAX_AGE_SECONDS else "DB_READY")
        return {"status": "READY" if reason == "DB_READY" else "DB_NOT_UPDATED", "reason": reason,
                "age_seconds": round(age, 3), "max_age_seconds": MAX_AGE_SECONDS,
                "snapshot_sha256": self.manifest["db_sha256"], "metadata": dict(meta)}

    def lookup(self, digest: bytes) -> bool:
        if self.con is None:
            raise RuntimeError("DB_UNAVAILABLE")
        self._query_deadline = time.monotonic() + 0.2
        return self.con.execute("SELECT 1 FROM hashes WHERE sha256=?", (sha_bytes(digest),)).fetchone() is not None

    def iter_hashes_for_rebuild(self):
        """Separate bounded management operation, never used by ZIP inspection."""
        if self.con is None:
            raise RuntimeError("DB_UNAVAILABLE")
        self._query_deadline = time.monotonic() + 30.0
        cursor = self.con.execute("SELECT sha256 FROM hashes")
        try:
            for row in cursor:
                yield row[0]
        finally:
            cursor.close()
            self._query_deadline = time.monotonic() + 0.2

    def close(self):
        if self.con is not None:
            self.con.close()
            self.con = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def delete_from_snapshot(manifest_path: Path, destination: Path, hashes: Iterable[str | bytes], *, prior_suppressions: frozenset[str] = frozenset(), profile: SnapshotProfile = SYNTHETIC_PROFILE) -> dict:
    """Offline deletion exercise: rebuild, suppress reintroduction, audit no raw SHA."""
    tokens = frozenset(revocation_tag(sha_bytes(value)) for value in hashes) | prior_suppressions
    with SQLiteProvider(manifest_path, profile=profile) as provider:
        if provider.manifest is None or provider.con is None:
            raise ValueError("SOURCE_SNAPSHOT_UNAVAILABLE")
        meta = provider.manifest["metadata"]
        manifest = _build_snapshot(destination, provider.iter_hashes_for_rebuild(), profile=profile,
                                            updated_at_utc=meta["updated_at_utc"], suppressed=tokens,
                                            deletion_revision=meta["deletion_revision"] + 1)
        new = json.loads(manifest.read_text())
        audit = {"schema": "orchard-ti-deletion/1", "data_kind": profile.data_kind,
                 "prior_snapshot_sha256": provider.manifest["db_sha256"], "replacement_snapshot_sha256": new["db_sha256"],
                 "removed_records": meta["record_count"] - new["metadata"]["record_count"],
                 "deletion_revision": new["metadata"]["deletion_revision"],
                 "suppression_tokens": sorted(tokens)}
        (destination / "deletion.json").write_text(json.dumps(audit, indent=2) + "\n")
        return audit
