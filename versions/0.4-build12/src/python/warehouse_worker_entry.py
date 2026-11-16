"""Pinned private app adapter. FD input only; no network or persistent writes.

The positive self-check never leaves a real digest in the report. It is separate
from archive matches. Clock/failure simulations are fixed, explicitly labelled
private verification modes; they do not mutate the database, attempt or OS clock.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import types

# BEGIN BUILD PINS
MODULE_PINS = {'r1_snapshot': 'ac8ea4f9fcafb7771a2a13149430d82b2ba4a830747a461237041da061f8e35a', 'threat_db': 'd62eab691cd9a9d70bb922b718def06101fa520b10ac1a22f69eb1bf4c370253', 'inspection': '3f4ad34cccee511a29cbebba7b2c7772021396c86ea7a9623e8964544e702ddf', 'feed_adapter': 'cadef777632d16742fad482de8f1a9d4e6ab2d0da2b399c20e534d082335a1f5', 'warehouse': '17fa694ff8945df6e258c912a4ef4c9fc78740bed6dec4c1b6d3c871871ec27e', 'bounded_reader': 'e5634454fccda7a2a62f93ab39b04f0eb0a686048ec07fbbd4d63328006bff72', 'policy': 'bc5f04d4d5e9d20cd42b02e4518c12095cd735adc7b30fd6386b92db5a8e7422'}
STORE_PINS = {'current.json': 'a4aedcb2bed48b941a92e098e863dacbc5a824f2cc77ad8aef08565a23df0a66', 'g-a5e38cbf56364a3ba6deac193ff7652c/manifest.json': '352a53441e2d6fae2d541d1ff5bc5a3df1bef2845ced8f23c43867e7b4c93f3e', 'g-a5e38cbf56364a3ba6deac193ff7652c/hashes.sqlite3': 'd778e4ec37eb300f87cee82a891cd85738f1ae095dfdadf27006db78c7537b95', 'g-a5e38cbf56364a3ba6deac193ff7652c/suppression.json': '4b6eb0d3474d76ffeff6022fd740b69eaa5b1ea296575b63138cdae067c39bc8'}
# END BUILD PINS

DB_SHA = "d778e4ec37eb300f87cee82a891cd85738f1ae095dfdadf27006db78c7537b95"
SOURCE_TIME = "2026-11-14T03:24:27Z"
RETRIEVED_TIME = "2026-11-14T03:38:48Z"
MODES = ("LIVE", "AFTER_25H_SIMULATION", "UPDATE_FAILED_SIMULATION")
LOOKUP_POLICY = "LOCAL_SNAPSHOT_AGE_ADVISORY_V1"
EXPECTED_COUNTS = {'full_added_unique': 198944, 'full_parsed_rows': 1173888, 'full_suppressed_row_occurrences': 0, 'full_unique_rows': None, 'latest_recent_also_observed_in_full_unique': 1169, 'latest_recent_overlap_old_unique': 116, 'latest_recent_unique': 1172, 'new_added_unique': 200000, 'old_also_observed_in_latest_full_unique': 99992, 'old_retained_unique': 100000, 'recent_added_unique': 1056, 'selected_unique': 300000}
FULL_GENERATED = '2026-11-15T23:33:04Z'
FULL_RETRIEVED = '2026-11-16T00:04:40Z'
RECENT_GENERATED = '2026-11-15T23:55:07Z'
RECENT_RETRIEVED = '2026-11-16T00:04:31Z'


def pinned_read(path, expected, cap):
    if any(p.is_symlink() for p in path.parents):
        raise ValueError("PIN_SYMLINK_PARENT")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > cap:
            raise ValueError("PIN_FILE_IDENTITY")
        data = stream.read(cap + 1)
    if len(data) > cap or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("PIN_CHECKSUM")
    return data


def load_modules():
    root = Path(__file__).absolute().parent
    for name in ("r1_snapshot", "threat_db", "inspection", "feed_adapter", "warehouse", "bounded_reader"):
        rel = "warehouse_code/warehouse.py" if name == "warehouse" else name + ".py"
        path = root / rel
        raw = pinned_read(path, MODULE_PINS[name], 131072)
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(raw, str(path), "exec"), module.__dict__)
    pinned_read(root / "POLICY.json", MODULE_PINS["policy"], 65536)
    return sys.modules["bounded_reader"]


def make_provider(root, mode):
    if mode not in MODES:
        raise ValueError("MODE_INVALID")
    w = load_modules()

    class PinnedBundleWarehouse(w.BoundedStore):
        def __init__(self, directory):
            # The immutable, sealed bundle is read-only under App Translocation.
            # Keep Warehouse's ownership/privacy/symlink and _load validation,
            # without requesting mkdir/write authority in an existing bundle.
            self.root = Path(directory).absolute()
            if self.root.is_symlink() or any(p.is_symlink() for p in self.root.parents):
                raise w.WarehouseError("STORE_SYMLINK_REJECTED")
            info = self.root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise w.WarehouseError("STORE_NOT_PRIVATE")
            actual = {str(p.relative_to(self.root)) for p in self.root.rglob("*") if not p.is_dir()}
            if actual != set(STORE_PINS):
                raise w.WarehouseError("BUNDLE_STORE_INVENTORY")
            for relative, expected in STORE_PINS.items():
                pinned_read(self.root / relative, expected, w.MAX_DB_BYTES)

    class AppProvider(w.BoundedProvider):
        def __init__(self, store):
            super().__init__(store)
            m = self.state["manifest"]
            s = m["source"]
            if (m["data_kind"] != w.REAL or m["database_sha256"] != DB_SHA
                    or m["total_unique_rows"] != 300000 or m["suppression_revision"] != 0
                    or m["negative_max_age_seconds"] != 90000
                    or m["update_interval_seconds"] != 86400 or m["automatic_updates"] is not False
                    or s["source_generated_at_utc"] != SOURCE_TIME or s["retrieved_at_utc"] != RETRIEVED_TIME
                    or m["counts"] != EXPECTED_COUNTS
                    or s["full"]["source_generated_at_utc"] != FULL_GENERATED
                    or s["full"]["retrieved_at_utc"] != FULL_RETRIEVED
                    or s["recent"]["source_generated_at_utc"] != RECENT_GENERATED
                    or s["recent"]["retrieved_at_utc"] != RECENT_RETRIEVED):
                raise ValueError("APP_WAREHOUSE_PROFILE")
            if mode == "AFTER_25H_SIMULATION":
                self.clock = lambda: max(time.time(), w.utc_timestamp(RETRIEVED_TIME) + 90001)
            # All 300,000 admitted existing SHA lookups, internally only. No malware bytes.
            self._current()
            # One already checksum/schema/suppression-validated, query-only
            # in-memory snapshot is held throughout this internal sweep.
            # Regular untrusted-ZIP lookups still use inherited lookup(),
            # including its before/after current-pointer check on every use.
            con = self.state["con"]
            if con.execute("PRAGMA query_only").fetchone() != (1,):
                raise ValueError("READ_ONLY_SNAPSHOT_REQUIRED")
            rows = con.execute("SELECT sha256 FROM hashes").fetchall()
            self.positive_count = sum(con.execute("SELECT 1 FROM hashes WHERE sha256=?", (row[0],)).fetchone() is not None for row in rows)
            self._current()
            if len(rows) != 300000 or self.positive_count != 300000:
                raise ValueError("INTERNAL_LOOKUP_SELF_CHECK")

        def describe(self):
            d = super().describe()
            m, s = self.state["manifest"], self.state["manifest"]["source"]
            if mode == "UPDATE_FAILED_SIMULATION" and d["reason"] != "DB_CLOCK_INVALID":
                d.update(status="DB_NOT_UPDATED", reason="UPDATE_FAILED")
            # Only elapsed age is informational. Integrity, current-pointer,
            # withdrawal, update-failure and invalid-clock checks still apply.
            if d["reason"] == "DB_STALE":
                d["status"] = "READY"
            now = self.clock()
            latest_retrieved = max(w.utc_timestamp(s[part]["retrieved_at_utc"])
                                   for part in ("full", "recent", "retained_snapshot"))
            if now < latest_retrieved:
                d.update(status="DB_NOT_UPDATED", reason="DB_CLOCK_INVALID")
            due = w.utc_timestamp(s["full"]["retrieved_at_utc"]) + 86400
            d.update(lookup_policy=LOOKUP_POLICY, freshness_blocks_lookup=False,
                     verification_mode=mode, evaluated_at_utc=w.stamp(now),
                     next_check_due_utc=w.stamp(due), update_due=now >= due,
                     retrieved_at_utc=s["retrieved_at_utc"],
                     Full_source_generated_at_utc=s["full"]["source_generated_at_utc"],
                     Full_retrieved_at_utc=s["full"]["retrieved_at_utc"],
                     Recent_source_generated_at_utc=s["recent"]["source_generated_at_utc"],
                     Recent_retrieved_at_utc=s["recent"]["retrieved_at_utc"],
                     expansion_counts=m["counts"],
                     declared_coverage_start_utc=s["recent"]["declared_coverage_start_utc"],
                     declared_coverage_end_utc=s["recent"]["declared_coverage_end_utc"],
                     update_attempt_status="FAILED" if mode == "UPDATE_FAILED_SIMULATION" else "SUCCESS",
                     update_attempt_at_utc=s["full"]["retrieved_at_utc"],
                     warehouse_self_check={"kind": "EXISTING_SHA_INTERNAL_LOOKUP_NOT_ZIP_MATCH",
                                           "checked": 300000, "matched": self.positive_count,
                                           "raw_sha_disclosed": False})
            d["metadata"].update(source_url="https://bazaar.abuse.ch/export/",
                updated_at_utc=s["source_generated_at_utc"],
                deletion_revision=m["suppression_revision"],
                license_basis="ST7343382_FREE_OSS_NO_REVENUE_PRIVATE_300K_CANDIDATE_PUBLIC_HOLD")
            return d

    return AppProvider(PinnedBundleWarehouse(root))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--verification-mode", choices=MODES, default="LIVE")
    args = parser.parse_args(argv)
    # Host supplies the exact admitted current.json, never a path from the ZIP.
    if args.manifest.name != "current.json":
        raise ValueError("ACTIVE_POINTER_PATH")
    with make_provider(args.manifest.parent, args.verification_mode) as provider:
        combined = sys.modules["warehouse"].inspect_zip(args.fd, provider)
        report = dict(combined["r1"])
        report["threat_intelligence"] = combined["threat_intelligence"]
        print(json.dumps(report, ensure_ascii=True, indent=2))
        return 2 if report["inspection_status"] == "UNKNOWN" else 0


if __name__ == "__main__":
    raise SystemExit(main())
