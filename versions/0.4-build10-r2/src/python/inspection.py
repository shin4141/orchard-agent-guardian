"""Private R1 composition: immutable ZIP snapshot + bounded local SHA lookup."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import select
import sqlite3
import stat
import struct
import time
import zipfile
import zlib

import r1_snapshot as r1
from threat_db import DisabledProvider, ThreatProvider


DEADLINE_SECONDS = 8.0
LABELS_JA = {
    "KNOWN_HASH_MATCH": "既知脅威のSHAに一致（合成テスト）",
    "NO_MATCH_IN_COVERED_DB": "対象DB内に一致なし（安全を意味しません）",
    "DB_NOT_UPDATED": "DBを利用できないか、更新が必要です",
    "UNINSPECTABLE": "照合を完了できない項目があります",
}


def _snapshot(source: str | os.PathLike | int, deadline: float) -> bytes:
    fd = os.dup(source) if isinstance(source, int) else os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        regular = stat.S_ISREG(before.st_mode)
        if not regular and not (isinstance(source, int) and stat.S_ISFIFO(before.st_mode)):
            raise ValueError("INPUT_NOT_REGULAR_FILE_OR_PIPE")
        if regular and (before.st_nlink != 1 or before.st_size > r1.LIMITS["archive_bytes"]):
            raise ValueError("INPUT_LINK_OR_ARCHIVE_SIZE_LIMIT")
        data = bytearray()
        while len(data) <= r1.LIMITS["archive_bytes"]:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                raise ValueError("INPUT_DEADLINE")
            chunk = os.read(fd, min(65_536, r1.LIMITS["archive_bytes"] + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) > r1.LIMITS["archive_bytes"]:
            raise ValueError("ARCHIVE_SIZE_LIMIT")
        if regular and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("INPUT_CHANGED_DURING_READ")
        return bytes(data)
    finally:
        os.close(fd)


def _threat_report(data: bytes, baseline: dict, provider: ThreatProvider, deadline: float, initial_error: str | None = None) -> dict:
    database = provider.describe()
    result = {
        "schema": "orchard-ti-inspection/1", "status": None, "database": database,
        "coverage": {"listed_entries": len(baseline["entries"]), "checked_files": 0,
                     "uninspectable_files": 0, "directories": 0, "bytes_hashed": 0,
                     "read_budget_reserved": 0, "complete": False},
        "entries": [], "unknown_conditions": [], "matches": [],
        "safety_proven": False, "authorizes_actions": False,
        "scope": "Outer ZIP member content SHA-256 only; no recursive archives or uploads.",
        "limitations": ["No match does not mean safe.", "Only the recorded snapshot and successfully read members are covered.",
                        ("Limited real SHA pilot only; not the complete MalwareBazaar corpus."
                         if (database.get("metadata") or {}).get("data_kind") == "MALWAREBAZAAR_REAL_SHA_PILOT"
                         else "Synthetic data only; no real MalwareBazaar data has been acquired or integrated.")],
    }
    archive_error = initial_error
    # R1's text heuristic unknowns do not change whether a binary can be hashed.
    # Container/global byte-limit failures do block the whole SHA phase.
    non_text_errors = [item["code"] for item in baseline["unknown_conditions"] if "entry_index" not in item and item["code"] != "NO_ALLOWLISTED_TEXT"]
    if non_text_errors:
        archive_error = non_text_errors[0]
    if not baseline["entries"] and not archive_error:
        archive_error = "NO_INSPECTABLE_MEMBERS"
    if archive_error:
        result["unknown_conditions"].append({"code": archive_error})
    else:
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
                infos = archive.infolist()
                for info, entry in zip(infos, baseline["entries"]):
                    item = {"entry_index": entry["index"], "path": entry["path"],
                            "source_role": "UNTRUSTED_ARCHIVE_DATA", "status": "UNINSPECTABLE", "sha256": None}
                    result["entries"].append(item)
                    if info.is_dir():
                        if not entry["issues"]:
                            item["status"] = "DIRECTORY_NOT_APPLICABLE"
                            result["coverage"]["directories"] += 1
                            continue
                    reason = entry["issues"][0] if entry["issues"] else None
                    remaining = r1.LIMITS["total_member_bytes"] - result["coverage"]["read_budget_reserved"]
                    cap = min(r1.LIMITS["member_bytes"], remaining)
                    if not reason and info.file_size > cap:
                        reason = "HASH_TOTAL_BYTE_LIMIT"
                    if time.monotonic() >= deadline:
                        reason = "HASH_DEADLINE"
                    if not reason:
                        # Reserve before decompression, including a failed read.
                        result["coverage"]["read_budget_reserved"] += info.file_size
                        try:
                            start = info.header_offset + 30 + sum(struct.unpack_from("<2H", data, info.header_offset + 26))
                            compressed = data[start:start + info.compress_size]
                            if info.compress_type == zipfile.ZIP_DEFLATED:
                                decoder = zlib.decompressobj(-15)
                                raw = decoder.decompress(compressed, info.file_size + 1)
                                if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                                    raise ValueError("ACTUAL_HASH_STREAM_MISMATCH_OR_LIMIT")
                            else:
                                raw = compressed
                            if len(raw) != info.file_size or len(raw) > cap or zlib.crc32(raw) != info.CRC:
                                raise ValueError("HASH_LENGTH_OR_CRC_MISMATCH")
                            if time.monotonic() >= deadline:
                                raise ValueError("HASH_DEADLINE")
                            digest = hashlib.sha256(raw).digest()
                            item["sha256"] = digest.hex()
                            result["coverage"]["checked_files"] += 1
                            result["coverage"]["bytes_hashed"] += len(raw)
                            # A stale but valid DB can still produce a positive match.
                            if database["metadata"] is None:
                                item["status"] = "DB_NOT_UPDATED"
                            else:
                                try:
                                    matched = provider.lookup(digest)
                                    item["status"] = "KNOWN_HASH_MATCH" if matched else "NO_MATCH_IN_COVERED_DB" if database["status"] == "READY" else "DB_NOT_UPDATED"
                                    if matched:
                                        result["matches"].append({"entry_index": entry["index"], "sha256": digest.hex()})
                                except (OSError, ValueError, RuntimeError, sqlite3.Error):
                                    item["status"] = "DB_NOT_UPDATED"
                                    database["status"] = "DB_NOT_UPDATED"
                                    database["reason"] = "DB_LOOKUP_FAILED"
                        except (OSError, ValueError, struct.error, zlib.error) as exc:
                            reason = str(exc) if isinstance(exc, ValueError) else "HASH_READ_FAILED_" + type(exc).__name__
                    if reason:
                        item["status"] = "UNINSPECTABLE"
                        item["sha256"] = None
                        item["reason"] = reason
                        result["coverage"]["uninspectable_files"] += 1
                        result["unknown_conditions"].append({"code": reason, "entry_index": entry["index"]})
        except (OSError, EOFError, ValueError, RuntimeError, zipfile.BadZipFile) as exc:
            result["unknown_conditions"].append({"code": "HASH_ARCHIVE_UNREADABLE_" + type(exc).__name__})
    complete = not result["unknown_conditions"] and result["coverage"]["checked_files"] > 0
    result["coverage"]["complete"] = complete
    result["status"] = (
        "KNOWN_HASH_MATCH" if result["matches"] else
        "UNINSPECTABLE" if not complete else
        "DB_NOT_UPDATED" if database["status"] != "READY" else
        "NO_MATCH_IN_COVERED_DB"
    )
    result["message_ja"] = ("既知脅威DBのSHAに一致" if result["status"] == "KNOWN_HASH_MATCH" and
        (database.get("metadata") or {}).get("data_kind") == "MALWAREBAZAAR_REAL_SHA_PILOT"
        else LABELS_JA[result["status"]])
    return result


def inspect_snapshot(data: bytes, provider: ThreatProvider | None = None, *, deadline: float | None = None) -> dict:
    """Compose both checks over exactly the same bytes; preserve R1 evidence."""
    deadline = time.monotonic() + DEADLINE_SECONDS if deadline is None else deadline
    baseline = r1.inspect_snapshot(data)
    ti = _threat_report(data, baseline, provider or DisabledProvider(), deadline)
    return {"schema": "orchard-r1-ti-candidate/1", "r1": baseline, "threat_intelligence": ti,
            "gate": "CAP" if baseline["gate"] == "CAP" and ti["status"] == "NO_MATCH_IN_COVERED_DB" else "HOLD",
            "safety_proven": False, "authorizes_actions": False}


def inspect_zip(source: str | os.PathLike | int, provider: ThreatProvider | None = None, *, deadline: float | None = None) -> dict:
    deadline = time.monotonic() + DEADLINE_SECONDS if deadline is None else deadline
    try:
        data = _snapshot(source, deadline)
    except (OSError, ValueError) as exc:
        baseline = r1._new_report()
        r1._unknown(baseline, str(exc) if isinstance(exc, ValueError) else "INPUT_UNREADABLE_" + type(exc).__name__)
        r1._finish(baseline)
        ti = _threat_report(b"", baseline, provider or DisabledProvider(), deadline, "INPUT_UNAVAILABLE")
        return {"schema": "orchard-r1-ti-candidate/1", "r1": baseline, "threat_intelligence": ti,
                "gate": "HOLD", "safety_proven": False, "authorizes_actions": False}
    return inspect_snapshot(data, provider, deadline=deadline)
