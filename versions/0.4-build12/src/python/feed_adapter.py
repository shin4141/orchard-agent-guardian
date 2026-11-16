"""Bounded SHA-only export adapter. Offline synthetic transport qualification."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from typing import BinaryIO

from threat_db import (MAX_AGE_SECONDS, SQLiteProvider, build_synthetic_snapshot,
                       _read_regular, revocation_tag, sha_bytes, utc_timestamp)


MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_ROWS = 3_000_000
MAX_PREAMBLE_LINES = 16
MAX_IMPORT_SECONDS = 30.0
DAILY_INTERVAL_SECONDS = 86_400
PUBLIC_EXPORT_DOCUMENTATION = "https://bazaar.abuse.ch/export/"
DATA_KIND = "SYNTHETIC_OFFICIAL_SHAPE_FIXTURE"
EPOCH = "1970-01-01T00:00:00Z"


class AdapterError(ValueError):
    """Stable codes only: never include input values, URLs or transport errors."""
    def __init__(self, code: str, line: int | None = None):
        self.code = code
        self.line = line
        super().__init__(code + (f":LINE_{line}" if line is not None else ""))


@dataclass(frozen=True)
class FormatProfile:
    """An explicit contract, not a claim about the login-hidden CSV schema."""
    profile_id: str
    kind: str
    columns: tuple[str, ...] = ()
    sha_column: str | None = None
    header_prefix: str = ""
    allow_preamble: bool = False
    allow_bom: bool = True

    def validate(self):
        if not re.fullmatch(r"[A-Z0-9_]{1,64}", self.profile_id):
            raise AdapterError("PROFILE_ID_INVALID")
        if self.kind not in {"csv", "text"} or self.header_prefix not in {"", "# "}:
            raise AdapterError("PROFILE_INVALID")
        if type(self.allow_preamble) is not bool or type(self.allow_bom) is not bool or type(self.columns) is not tuple:
            raise AdapterError("PROFILE_INVALID")
        if self.kind == "csv":
            if not 1 <= len(self.columns) <= 32 or len(set(self.columns)) != len(self.columns) or self.sha_column not in self.columns:
                raise AdapterError("PROFILE_COLUMNS_INVALID")
            if any(not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item) for item in self.columns):
                raise AdapterError("PROFILE_COLUMNS_INVALID")
        elif self.columns or self.sha_column is not None or self.header_prefix:
            raise AdapterError("TEXT_PROFILE_HAS_NO_COLUMNS")


CSV_SHA256_FIXTURE = FormatProfile("SYNTHETIC_CSV_SHA256_V1", "csv", ("sha256_hash",), "sha256_hash")
CSV_METADATA_FIXTURE = FormatProfile("SYNTHETIC_CSV_METADATA_V1", "csv",
    ("first_seen", "sha256_hash", "malware_family", "tag", "entry_url"), "sha256_hash", "# ", True)
TEXT_SHA256_FIXTURE = FormatProfile("SYNTHETIC_TEXT_SHA256_V1", "text", allow_preamble=True)


@dataclass(frozen=True)
class TransferReceipt:
    """Supplied by trusted transport; tests use a synthetic transport double.

    Locally counting/hashing a body does not independently prove completeness.
    Unknown completion facts must remain unknown, never guessed by the parser.
    """
    expected_bytes: int
    expected_sha256: str
    expected_records: int
    completed: bool
    http_status: int = 200
    content_encoding: str = "identity"

    def validate(self):
        if self.completed is not True or self.http_status != 200:
            raise AdapterError("TRANSFER_INCOMPLETE_OR_HTTP_FAILURE")
        if self.content_encoding != "identity":
            raise AdapterError("COMPRESSED_EXPORT_NOT_QUALIFIED")
        if type(self.expected_bytes) is not int or not 0 < self.expected_bytes <= MAX_INPUT_BYTES:
            raise AdapterError("TRANSFER_SIZE_INVALID_OR_LIMIT")
        if type(self.expected_records) is not int or not 0 < self.expected_records <= MAX_ROWS:
            raise AdapterError("TRANSFER_RECORD_COUNT_UNKNOWN_OR_LIMIT")
        if not isinstance(self.expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.expected_sha256):
            raise AdapterError("TRANSFER_SHA256_REQUIRED")


@dataclass(frozen=True)
class ExportContext:
    dataset: str
    retrieved_at_utc: str
    generated_at_utc: str | None
    data_kind: str = DATA_KIND
    coverage_start_utc: str | None = None
    coverage_end_utc: str | None = None

    def validate(self, now: float):
        if self.data_kind != DATA_KIND:
            raise AdapterError("REAL_DATA_GATE_CLOSED")
        if self.dataset not in {"recent", "full"}:
            raise AdapterError("DATASET_NOT_HASH_EXPORT")
        try:
            retrieved = utc_timestamp(self.retrieved_at_utc)
            generated = utc_timestamp(self.generated_at_utc) if self.generated_at_utc is not None else None
            begin = utc_timestamp(self.coverage_start_utc) if self.coverage_start_utc is not None else None
            end = utc_timestamp(self.coverage_end_utc) if self.coverage_end_utc is not None else None
        except (ValueError, TypeError):
            raise AdapterError("SOURCE_TIMESTAMP_INVALID") from None
        if retrieved > now or now - retrieved > MAX_AGE_SECONDS:
            raise AdapterError("RETRIEVAL_FUTURE_OR_STALE")
        if generated is not None and (generated > retrieved or now - generated > MAX_AGE_SECONDS):
            raise AdapterError("SOURCE_FUTURE_OR_STALE")
        if (begin is None) != (end is None) or (begin is not None and (begin > end or generated is None or end > generated)):
            raise AdapterError("COVERAGE_INVALID")
        if begin is not None and self.dataset == "recent" and end - begin != 48 * 3600:
            raise AdapterError("RECENT_DECLARED_WINDOW_MISMATCH")


@dataclass(frozen=True)
class SuppressionLedger:
    revision: int = 0
    tokens: frozenset[str] = frozenset()
    withdrawn: bool = False
    request_refs: tuple[str, ...] = ()

    def validate(self):
        if type(self.revision) is not int or self.revision < 0 or type(self.withdrawn) is not bool:
            raise AdapterError("SUPPRESSION_LEDGER_INVALID")
        if type(self.tokens) is not frozenset or type(self.request_refs) is not tuple:
            raise AdapterError("SUPPRESSION_LEDGER_INVALID")
        if len(self.tokens) > MAX_ROWS or any(not isinstance(t, str) or not re.fullmatch(r"[0-9a-f]{64}", t) for t in self.tokens):
            raise AdapterError("SUPPRESSION_LEDGER_INVALID")
        if any(not re.fullmatch(r"[A-Z0-9-]{1,48}", ref) for ref in self.request_refs):
            raise AdapterError("SUPPRESSION_REQUEST_REF_INVALID")

    def as_dict(self):
        self.validate()
        return {"schema": "orchard-ti-suppression-ledger/1", "revision": self.revision,
                "tokens": sorted(self.tokens), "withdrawn": self.withdrawn, "request_refs": list(self.request_refs)}

    @classmethod
    def from_dict(cls, value: dict):
        if not isinstance(value, dict) or set(value) != {"schema", "revision", "tokens", "withdrawn", "request_refs"} or value["schema"] != "orchard-ti-suppression-ledger/1":
            raise AdapterError("SUPPRESSION_LEDGER_INVALID")
        if not isinstance(value["tokens"], list) or not isinstance(value["request_refs"], list):
            raise AdapterError("SUPPRESSION_LEDGER_INVALID")
        try:
            ledger = cls(value["revision"], frozenset(value["tokens"]), value["withdrawn"], tuple(value["request_refs"]))
            ledger.validate()
        except (TypeError, ValueError):
            raise AdapterError("SUPPRESSION_LEDGER_INVALID") from None
        return ledger

    @classmethod
    def from_legacy_deletion(cls, audit: dict, request_ref: str):
        if not isinstance(audit, dict) or audit.get("schema") != "orchard-ti-deletion/1" or audit.get("data_kind") != "SYNTHETIC_ONLY" or not isinstance(audit.get("suppression_tokens"), list):
            raise AdapterError("LEGACY_DELETION_AUDIT_INVALID")
        try:
            ledger = cls(audit["deletion_revision"], frozenset(audit["suppression_tokens"]), False, (request_ref,))
            ledger.validate()
        except (KeyError, ValueError, TypeError):
            raise AdapterError("LEGACY_DELETION_AUDIT_INVALID") from None
        return ledger

    @property
    def sha256(self):
        return hashlib.sha256(json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def exclude(self, hashes, request_ref: str):
        updated = SuppressionLedger(self.revision + 1, self.tokens | frozenset(revocation_tag(sha_bytes(value)) for value in hashes),
                                    self.withdrawn, self.request_refs + (request_ref,))
        updated.validate()
        return updated

    def require_successor(self, previous: SuppressionLedger | None):
        self.validate()
        if previous is not None:
            previous.validate()
            if self.revision < previous.revision or not previous.tokens <= self.tokens or (previous.withdrawn and not self.withdrawn) or not set(previous.request_refs) <= set(self.request_refs):
                raise AdapterError("SUPPRESSION_ROLLBACK_OR_REMOVAL")
            if self.revision == previous.revision and self.sha256 != previous.sha256:
                raise AdapterError("SUPPRESSION_REVISION_REUSED")
        if self.withdrawn:
            raise AdapterError("PROVIDER_PERMISSION_WITHDRAWN")


def official_fetch_plan(dataset: str, kind: str) -> dict:
    if dataset not in {"recent", "full"} or kind not in {"csv", "text"}:
        raise AdapterError("FETCH_PLAN_NOT_HASH_EXPORT")
    return {"schema": "orchard-ti-official-fetch-plan/1", "dataset": dataset, "format": kind,
            "documentation": PUBLIC_EXPORT_DOCUMENTATION, "scheduled": False,
            "intended_interval_seconds": DAILY_INTERVAL_SECONDS, "real_acquisition_enabled": False,
            "export_endpoint": None, "endpoint_status": "AUTHENTICATED_DOCUMENTATION_REQUIRED",
            "export_authentication": "Credential-bearing official export URL; never persist or log it",
            "community_api": {"endpoint": "https://mb-api.abuse.ch/api/v1/", "method": "POST",
                              "authentication_header_name": "Auth-Key", "response_sha256_key": "sha256_hash"},
            "sample_download_allowed": False, "scraping_allowed": False}


class _Reader:
    def __init__(self, source: BinaryIO, receipt: TransferReceipt, deadline: float):
        self.source, self.receipt, self.deadline = source, receipt, deadline
        self.total = self.line_number = 0
        self.hasher = hashlib.sha256()

    def lines(self):
        while True:
            if time.monotonic() >= self.deadline:
                raise AdapterError("IMPORT_DEADLINE", self.line_number)
            try:
                raw = self.source.readline(MAX_LINE_BYTES + 1)
            except Exception:
                raise AdapterError("TRANSFER_READ_FAILED", self.line_number) from None
            if time.monotonic() >= self.deadline:
                raise AdapterError("IMPORT_DEADLINE", self.line_number)
            if not isinstance(raw, bytes):
                raise AdapterError("BINARY_STREAM_REQUIRED")
            if not raw:
                return
            self.line_number += 1
            self.total += len(raw)
            if self.total > MAX_INPUT_BYTES or self.total > self.receipt.expected_bytes:
                raise AdapterError("INPUT_BYTE_LIMIT_OR_LENGTH_EXCEEDED", self.line_number)
            if len(raw) > MAX_LINE_BYTES:
                raise AdapterError("INPUT_LINE_LIMIT", self.line_number)
            self.hasher.update(raw)
            if not raw.endswith(b"\n"):
                raise AdapterError("UNTERMINATED_RECORD_OR_TRUNCATION", self.line_number)
            raw = raw[:-1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeError:
                raise AdapterError("INPUT_ENCODING_INVALID", self.line_number) from None
            yield text

    def finish(self, records: int):
        if self.total != self.receipt.expected_bytes:
            raise AdapterError("TRANSFER_LENGTH_MISMATCH")
        if not hmac.compare_digest(self.hasher.hexdigest(), self.receipt.expected_sha256):
            raise AdapterError("TRANSFER_SHA256_MISMATCH")
        if records != self.receipt.expected_records:
            raise AdapterError("TRANSFER_RECORD_COUNT_MISMATCH")


def _parse(reader: _Reader, profile: FormatProfile, ledger: SuppressionLedger, stats: dict):
    got_header = profile.kind == "text"
    comments = 0
    for text in reader.lines():
        line = reader.line_number
        if line == 1 and text.startswith("\ufeff") and profile.allow_bom:
            text = text[1:]
        if not text or not text.isprintable():
            raise AdapterError("EMPTY_OR_CONTROL_RECORD", line)
        if not got_header:
            possible_header = text[len(profile.header_prefix):] if text.startswith(profile.header_prefix) else None
            try:
                fields = next(csv.reader([possible_header], strict=True)) if possible_header is not None else []
            except (csv.Error, StopIteration):
                fields = []
            if tuple(fields) == profile.columns:
                got_header = True
                continue
            if not text.startswith("# "):
                raise AdapterError("CSV_HEADER_MISSING_DUPLICATE_OR_MISMATCH", line)
        if text.startswith("# "):
            if not profile.allow_preamble or stats["records_seen"] or got_header and profile.kind == "csv":
                raise AdapterError("UNEXPECTED_COMMENT_RECORD", line)
            comments += 1
            if comments > MAX_PREAMBLE_LINES:
                raise AdapterError("PREAMBLE_LINE_LIMIT", line)
            continue
        if profile.kind == "csv":
            try:
                fields = next(csv.reader([text], strict=True))
            except (csv.Error, StopIteration):
                raise AdapterError("CSV_SYNTAX_INVALID", line) from None
            if len(fields) != len(profile.columns):
                raise AdapterError("CSV_COLUMN_COUNT_MISMATCH", line)
            value = fields[profile.columns.index(profile.sha_column)]
        else:
            value = text
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise AdapterError("INVALID_SHA256", line)
        stats["records_seen"] += 1
        if stats["records_seen"] > MAX_ROWS or stats["records_seen"] > reader.receipt.expected_records:
            raise AdapterError("RECORD_COUNT_LIMIT", line)
        digest = bytes.fromhex(value)
        if ledger.tokens and revocation_tag(digest) in ledger.tokens:
            stats["suppressed_rows"] += 1
            continue
        stats["accepted_rows"] += 1
        yield digest
    if not got_header or not stats["records_seen"]:
        raise AdapterError("CSV_HEADER_OR_DATA_MISSING")
    reader.finish(stats["records_seen"])


def ingest_export(source: BinaryIO, destination: Path, *, profile: FormatProfile,
                  context: ExportContext, transfer: TransferReceipt, ledger: SuppressionLedger,
                  previous_ledger: SuppressionLedger | None = None, previous_snapshot: Path | None = None,
                  now: float | None = None) -> dict:
    """Build privately, verify the entire transfer, then publish ONE new DB.

    No current pointer, existing DB or scheduler is modified. Failed parsing,
    truncation or provenance validation never publishes a partial replacement.
    """
    began = time.monotonic()
    now = time.time() if now is None else now
    profile.validate(); context.validate(now); transfer.validate()
    if previous_snapshot is not None:
        try:
            previous_snapshot = Path(previous_snapshot)
            prior = json.loads(_read_regular(previous_snapshot / "ingestion.json", 16_384))
            prior_ledger = SuppressionLedger.from_dict(json.loads(_read_regular(previous_snapshot / "suppression.json", 256 * 1024 * 1024)))
            with SQLiteProvider(previous_snapshot / "snapshot.json", now=now) as provider:
                if provider.manifest is None or prior["schema"] != "orchard-ti-export-ingestion/1" or prior["data_kind"] != DATA_KIND or prior["database_sha256"] != provider.manifest["db_sha256"] or prior["suppression_ledger_sha256"] != prior_ledger.sha256:
                    raise AdapterError("PRIOR_SNAPSHOT_IDENTITY_INVALID")
            if previous_ledger is not None and previous_ledger.sha256 != prior_ledger.sha256:
                raise AdapterError("PRIOR_SUPPRESSION_IDENTITY_MISMATCH")
            previous_ledger = prior_ledger
            old_generated = prior["source_generated_at_utc"]
            if old_generated is not None:
                if context.generated_at_utc is None or utc_timestamp(context.generated_at_utc) < utc_timestamp(old_generated):
                    raise AdapterError("SOURCE_GENERATION_ROLLBACK_OR_UNKNOWN")
                if context.generated_at_utc == old_generated and transfer.expected_sha256 != prior["source_snapshot_sha256"]:
                    raise AdapterError("SOURCE_GENERATION_REUSED_WITH_DIFFERENT_BYTES")
            if utc_timestamp(context.retrieved_at_utc) < utc_timestamp(prior["retrieved_at_utc"]):
                raise AdapterError("RETRIEVAL_TIME_ROLLBACK")
        except AdapterError:
            raise
        except Exception:
            raise AdapterError("PRIOR_SNAPSHOT_IDENTITY_INVALID") from None
    ledger.require_successor(previous_ledger)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise AdapterError("DESTINATION_MUST_BE_NEW")
    if any(p.is_symlink() for p in destination.parents):
        raise AdapterError("DESTINATION_SYMLINK_PARENT")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".feed-adapter-", dir=destination.parent))
    stats = {"records_seen": 0, "accepted_rows": 0, "suppressed_rows": 0}
    reader = _Reader(source, transfer, began + MAX_IMPORT_SECONDS)
    try:
        snapshot = build_synthetic_snapshot(staging / "snapshot", _parse(reader, profile, ledger, stats),
            updated_at_utc=context.generated_at_utc or EPOCH, suppressed=ledger.tokens, deletion_revision=ledger.revision)
        manifest = json.loads(snapshot.read_text())
        stats["unique_stored"] = manifest["metadata"]["record_count"]
        stats["duplicate_accepted_rows"] = stats["accepted_rows"] - stats["unique_stored"]
        provenance = {
            "schema": "orchard-ti-export-ingestion/1", "data_kind": DATA_KIND,
            "status": "FIXTURE_IMPORTED" if context.generated_at_utc is not None else "QUARANTINED_FRESHNESS_UNKNOWN",
            "source_documentation": PUBLIC_EXPORT_DOCUMENTATION, "source_dataset": context.dataset,
            "format_profile": profile.profile_id, "format_schema_confirmed_with_authenticated_export": False,
            "retrieved_at_utc": context.retrieved_at_utc, "source_generated_at_utc": context.generated_at_utc,
            "coverage": {"start_utc": context.coverage_start_utc, "end_utc": context.coverage_end_utc,
                         "declared_recent_window_hours": 48 if context.dataset == "recent" else None,
                         "member_first_seen_min_utc": None, "member_first_seen_max_utc": None,
                         "basis": "DECLARED_EXPORT_WINDOW_NOT_OBSERVED_MEMBER_TIMESTAMPS"},
            "counts": stats, "source_bytes": reader.total, "source_snapshot_sha256": reader.hasher.hexdigest(),
            "database_sha256": manifest["db_sha256"], "database_bytes": manifest["db_bytes"],
            "retained_sample_fields": ["sha256"], "suppression_revision": ledger.revision,
            "suppression_ledger_sha256": ledger.sha256, "permission_ticket": "ST7343382",
            "permission_original_sha256": "4381705ad2401cda8e7cd09bc5f94d6964771ee9601ffeae5031851b29409d8f",
            "next_update_policy_seconds": DAILY_INTERVAL_SECONDS, "automatic_update_enabled": False,
            "freshness_limit_seconds": MAX_AGE_SECONDS, "real_data_downloaded": False,
            "attribution": "Synthetic fixture; no abuse.ch data included",
        }
        (staging / "snapshot/ingestion.json").write_text(json.dumps(provenance, indent=2, ensure_ascii=True) + "\n")
        (staging / "snapshot/suppression.json").write_text(json.dumps(ledger.as_dict(), indent=2) + "\n")
        validation_now = now + (time.monotonic() - began)
        context.validate(validation_now)
        with SQLiteProvider(snapshot, now=validation_now) as provider:
            if provider.manifest is None:
                raise AdapterError("BUILT_DATABASE_VALIDATION_FAILED")
            if context.generated_at_utc is not None and provider.describe()["status"] != "READY":
                raise AdapterError("BUILT_DATABASE_NOT_FRESH")
        if time.monotonic() >= reader.deadline:
            raise AdapterError("IMPORT_DEADLINE")
        # Destination race cannot replace a nonempty installed snapshot. The
        # caller must choose a fresh generation directory, never an active DB.
        if destination.exists() or destination.is_symlink():
            raise AdapterError("DESTINATION_MUST_BE_NEW")
        os.rename(staging / "snapshot", destination)
        return provenance
    except AdapterError:
        raise
    except Exception:
        raise AdapterError("IMPORT_STORAGE_OR_BUILD_FAILED") from None
    finally:
        shutil.rmtree(staging)
