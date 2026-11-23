"""Private R1 composition: immutable ZIP snapshot + bounded local SHA lookup."""

from __future__ import annotations

import io
import os
from pathlib import Path
import select
import sqlite3
import stat
import time

import r1_snapshot as r1
from threat_db import DisabledProvider, ThreatProvider


LABELS_JA = {
    "KNOWN_HASH_MATCH": "既知脅威のSHAに一致（合成テスト）",
    "NO_MATCH_IN_COVERED_DB": "対象DB内に一致なし（安全を意味しません）",
    "DB_NOT_UPDATED": "DBを利用できないか、更新が必要です",
    "UNINSPECTABLE": "照合を完了できない項目があります",
    "NO_ITEMS_IN_SCOPE": "SHA照合の対象ファイルはありません",
}


def _snapshot(source: str | os.PathLike | int, deadline: float) -> bytes:
    fd = os.dup(source) if isinstance(source, int) else os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        regular = stat.S_ISREG(before.st_mode)
        if not regular and not (isinstance(source, int) and stat.S_ISFIFO(before.st_mode)):
            raise ValueError("INPUT_NOT_REGULAR_FILE_OR_PIPE")
        if regular and before.st_nlink != 1:
            raise ValueError("INPUT_LINK_OR_ARCHIVE_SIZE_LIMIT")
        cap = r1.LIMITS["archive_bytes"]
        if regular and before.st_size > cap:
            raise ValueError("ARCHIVE_SIZE_LIMIT")
        # Keep the sealed snapshot in one buffer; the parser reads these bytes
        # without a second bytearray-to-bytes allocation on the supported runtime.
        with io.BytesIO() as data:
            while data.tell() <= cap:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                    raise ValueError("INPUT_DEADLINE")
                chunk = os.read(fd, min(r1.CHUNK_BYTES, cap + 1 - data.tell()))
                if not chunk:
                    break
                data.write(chunk)
            if data.tell() > cap:
                raise ValueError("ARCHIVE_SIZE_LIMIT")
            after = os.fstat(fd)
            if regular and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("INPUT_CHANGED_DURING_READ")
            return data.getvalue()
    finally:
        os.close(fd)


def _threat_report(baseline: dict, provider: ThreatProvider, deadline: float,
                   initial_error: str | None = None) -> dict:
    database = provider.describe()
    coverage = {"listed_entries": len(baseline["entries"]), "checked_files": 0,
                "uninspectable_files": 0, "directories": 0, "bytes_hashed": 0,
                "read_budget_reserved": 0, "complete": False}
    result = {
        "schema": "orchard-ti-inspection/1", "status": None, "database": database, "coverage": coverage,
        "entries": [], "unknown_conditions": [], "matches": [],
        "safety_proven": False, "authorizes_actions": False,
        "scope": "Outer ZIP member content SHA-256 only; no recursive archives or uploads.",
        "limitations": ["No match does not mean safe.", "Only the recorded snapshot and successfully read members are covered.",
                        ("Limited real SHA pilot only; not the complete MalwareBazaar corpus."
                         if (database.get("metadata") or {}).get("data_kind") == "MALWAREBAZAAR_REAL_SHA_PILOT"
                         else "Synthetic data only; no real MalwareBazaar data has been acquired or integrated.")],
    }
    bounded_warehouse = (database.get("metadata") or {}).get("data_kind") == "MALWAREBAZAAR_REAL_SHA_BOUNDED_SUBSET"
    if bounded_warehouse:
        result["limitations"][2] = "Limited real SHA warehouse of admitted Recent files; not the full MalwareBazaar corpus."
    no_items = (baseline["scope_detail"]["structure_status"] == "CHECKED" and
                baseline["inspection_status"] == "COMPLETE" and
                baseline["coverage"]["directories"] == len(baseline["entries"]))
    if not baseline["entries"] and not no_items:
        errors = baseline["unknown_conditions"]
        result["unknown_conditions"].append({
            "code": initial_error or (errors[0]["code"] if errors else "NO_INSPECTABLE_MEMBERS")
        })
    for entry in baseline["entries"]:
        index = entry["index"]
        item = {"entry_index": index, "path": entry["path"], "source_role": "UNTRUSTED_ARCHIVE_DATA",
                "status": "UNINSPECTABLE", "sha256": None}
        result["entries"].append(item)
        coverage["read_budget_reserved"] += entry["read_budget_reserved"]
        if entry["text_status"] == "DIRECTORY":
            item["status"] = "DIRECTORY_NOT_APPLICABLE"
            coverage["directories"] += 1
            continue
        digest = entry.get("verified_sha256")
        reason = None
        if digest is None:
            reason = entry["issues"][0] if entry["issues"] else "MEMBER_NOT_READ"
        else:
            item["sha256"] = digest
            coverage["bytes_hashed"] += entry["uncompressed_bytes"]
            if time.monotonic() >= deadline:
                reason = "HASH_LOOKUP_DEADLINE"
            else:
                try:
                    matched = database["metadata"] is not None and provider.lookup(bytes.fromhex(digest))
                    item["status"] = ("KNOWN_HASH_MATCH" if matched else
                                      "NO_MATCH_IN_COVERED_DB" if database["status"] == "READY" else "DB_NOT_UPDATED")
                    coverage["checked_files"] += 1
                    if matched:
                        result["matches"].append({"entry_index": index, "sha256": digest})
                except (OSError, ValueError, RuntimeError, sqlite3.Error):
                    reason = "DB_LOOKUP_FAILED"
        if reason:
            coverage["uninspectable_files"] += 1
            item["reason"] = reason
            result["unknown_conditions"].append({"code": reason, "entry_index": index})
    complete = not result["unknown_conditions"] and (coverage["checked_files"] > 0 or no_items)
    coverage["complete"] = complete
    result["status"] = (
        "KNOWN_HASH_MATCH" if result["matches"] else
        "NO_ITEMS_IN_SCOPE" if no_items else
        "UNINSPECTABLE" if not complete else
        "DB_NOT_UPDATED" if database["status"] != "READY" else
        "NO_MATCH_IN_COVERED_DB"
    )
    result["message_ja"] = ("既知脅威DBのSHAに一致" if result["status"] == "KNOWN_HASH_MATCH" and
        (database.get("metadata") or {}).get("data_kind") == "MALWAREBAZAAR_REAL_SHA_PILOT"
        else LABELS_JA[result["status"]])
    if bounded_warehouse and result["status"] == "KNOWN_HASH_MATCH":
        freshness = "DBは更新未確認です。" if database["status"] != "READY" else ""
        result["message_ja"] = f"限定的な実SHA倉庫の収録SHAに一致。{freshness}安全性は判定しません。"
    return result


FORMAT_EXCLUSIONS = frozenset({
    *r1.TEXT_FORMAT_EXCLUSIONS, "NESTED_FORMAT_UNSUPPORTED",
})
CHECK_FAILURE_PREFIXES = (
    "MALFORMED_", "INPUT_UNREADABLE_", "INPUT_CHANGED_", "ZIP_UNREADABLE_",
    "LOCAL_HEADER_", "MEMBER_SPAN_", "MEMBER_STREAM_", "TAR_STRUCTURE_", "GZIP_STRUCTURE_",
)


def _inspection_presentation(report: dict, threat: dict) -> str:
    """Summarize evidence for display without changing either inspection gate."""
    if report["findings"] or threat["matches"]:
        return "DETECTED"

    scope = report["scope_detail"]
    reasons = set(scope["blocking_reasons"])
    nested = scope["nested"]
    if nested:
        reasons.discard("NESTED_CONTENT_UNRESOLVED")
        for item in nested:
            reasons.update(item["reasons"])
    lookup_reasons = {row["code"] for row in threat["unknown_conditions"]}
    if (any(code.startswith(CHECK_FAILURE_PREFIXES) or code.endswith("_MISMATCH")
            for code in reasons | lookup_reasons)
            or bool(lookup_reasons & {"DB_LOOKUP_FAILED", "INPUT_UNAVAILABLE"})
            or any(row["kind"] != "OTHER_ARCHIVE" and "NESTED_FORMAT_UNSUPPORTED" in row["reasons"]
                   for row in nested)
            or (threat["status"] != "NO_ITEMS_IN_SCOPE" and threat["database"]["status"] != "READY")):
        return "CHECK_FAILED"

    sha_verified = threat["status"] in {"NO_MATCH_IN_COVERED_DB", "NO_ITEMS_IN_SCOPE"}
    if report["inspection_status"] == "COMPLETE" and sha_verified:
        return "COMPLETE"
    if reasons and reasons <= FORMAT_EXCLUSIONS and sha_verified and scope["structure_status"] == "CHECKED":
        return "OUT_OF_SCOPE_FORMATS"
    return "PARTIAL"


def _compose(baseline: dict, threat: dict) -> dict:
    # CAP describes completed applicable checks. The parent still holds every handoff.
    covered = (baseline["instruction_scope"]["status"] in {"NO_FINDINGS", "NO_TARGETS"}
               and baseline["scope_detail"]["structure_status"] == "CHECKED"
               and threat["status"] in {"NO_MATCH_IN_COVERED_DB", "NO_ITEMS_IN_SCOPE"})
    return {"schema": "orchard-r1-ti-candidate/1", "r1": baseline, "threat_intelligence": threat,
            "inspection_presentation": _inspection_presentation(baseline, threat),
            "gate": "CAP" if covered else "HOLD",
            "safety_proven": False, "authorizes_actions": False}


def inspect_snapshot(data: bytes, provider: ThreatProvider | None = None, *,
                     deadline: float | None = None, thorough: bool = False, on_resolved=None) -> dict:
    """Compose the applicable inspection checks over exactly the same bytes."""
    deadline = time.monotonic() + (r1.THOROUGH_SECONDS if thorough else r1.DEADLINE_SECONDS) if deadline is None else deadline
    baseline = r1.inspect_snapshot(data, deadline=deadline, thorough=thorough, on_resolved=on_resolved)
    return _compose(baseline, _threat_report(baseline, provider or DisabledProvider(), deadline))


def inspect_zip(source: str | os.PathLike | int, provider: ThreatProvider | None = None, *,
                deadline: float | None = None, thorough: bool = False, on_resolved=None) -> dict:
    deadline = time.monotonic() + (r1.THOROUGH_SECONDS if thorough else r1.DEADLINE_SECONDS) if deadline is None else deadline
    try:
        data = _snapshot(source, deadline)
    except (OSError, ValueError) as exc:
        baseline = r1._new_report(r1.THOROUGH_LIMITS if thorough else r1.LIMITS)
        if thorough:
            baseline["inspection_profile"] = "THOROUGH"
        r1._unknown(baseline, str(exc) if isinstance(exc, ValueError) else "INPUT_UNREADABLE_" + type(exc).__name__)
        r1._finish(baseline)
        ti = _threat_report(baseline, provider or DisabledProvider(), deadline, "INPUT_UNAVAILABLE")
        return _compose(baseline, ti)
    return inspect_snapshot(data, provider, deadline=deadline, thorough=thorough, on_resolved=on_resolved)
