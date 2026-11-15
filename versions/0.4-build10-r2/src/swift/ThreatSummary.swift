import Foundation

// Private R1 report extension. It adds no action, network call or extraction.
struct R1ThreatMetadata: Decodable {
    let provider: String, source_url: String, data_kind: String, updated_at_utc: String
    let coverage: String, attribution: String, license_basis: String
    let fields: [String]
    let record_count: Int, deletion_revision: Int
}
struct WarehouseSelfCheck: Decodable {
    let kind: String
    let checked: Int, matched: Int
    let raw_sha_disclosed: Bool
}
struct R1ThreatDatabase: Decodable {
    let status: String, reason: String
    let metadata: R1ThreatMetadata?
    let snapshot_sha256: String?
    let max_age_seconds: Int
    let age_seconds: Double
    let next_check_due_utc: String
    let update_due: Bool
    let lookup_policy: String
    let freshness_blocks_lookup: Bool
    let verification_mode: String, evaluated_at_utc: String, retrieved_at_utc: String
    let declared_coverage_start_utc: String, declared_coverage_end_utc: String
    let update_attempt_status: String, update_attempt_at_utc: String
    let Full_source_generated_at_utc: String, Full_retrieved_at_utc: String
    let warehouse_self_check: WarehouseSelfCheck
    let automatic_updates: Bool, safety_proven: Bool, authorizes_actions: Bool

    var policyValid: Bool {
        let formatter = ISO8601DateFormatter()
        guard let evaluated = formatter.date(from: evaluated_at_utc),
              let generated = formatter.date(from: "2026-11-14T03:24:27Z"),
              let retrieved = formatter.date(from: retrieved_at_utc),
              let due = formatter.date(from: next_check_due_utc),
              ["LIVE", "AFTER_25H_SIMULATION", "UPDATE_FAILED_SIMULATION"].contains(verification_mode),
              retrieved_at_utc == "2026-11-14T03:38:48Z",
              declared_coverage_start_utc == "2026-11-12T03:24:27Z",
              declared_coverage_end_utc == "2026-11-14T03:24:27Z",
              Full_source_generated_at_utc == "2026-11-14T22:27:04Z",
              Full_retrieved_at_utc == "2026-11-14T23:53:54Z",
              let fullGenerated = formatter.date(from: Full_source_generated_at_utc),
              let fullRetrieved = formatter.date(from: Full_retrieved_at_utc),
              generated <= fullGenerated, retrieved <= fullRetrieved, fullGenerated <= fullRetrieved,
              update_attempt_at_utc == Full_retrieved_at_utc,
              ["SUCCESS", "FAILED"].contains(update_attempt_status), max_age_seconds == 90000,
              lookup_policy == "LOCAL_SNAPSHOT_AGE_ADVISORY_V1", !freshness_blocks_lookup,
              age_seconds.isFinite, abs(age_seconds - evaluated.timeIntervalSince(generated)) < 2,
              due.timeIntervalSince(retrieved) == 86400,
              update_due == (evaluated >= due),
              !automatic_updates, !safety_proven, !authorizes_actions,
              warehouse_self_check.kind == "EXISTING_SHA_INTERNAL_LOOKUP_NOT_ZIP_MATCH",
              warehouse_self_check.checked == 100000, warehouse_self_check.matched == 100000,
              !warehouse_self_check.raw_sha_disclosed else { return false }
        if verification_mode == "AFTER_25H_SIMULATION" && evaluated.timeIntervalSince(retrieved) < 90001 { return false }
        if verification_mode == "UPDATE_FAILED_SIMULATION" && update_attempt_status != "FAILED" { return false }
        let expected = evaluated < retrieved ? "DB_CLOCK_INVALID" :
            update_attempt_status == "FAILED" ? "UPDATE_FAILED" :
            evaluated.timeIntervalSince(generated) > 90000 ? "DB_STALE" : "DB_READY"
        return reason == expected && status == (["DB_READY", "DB_STALE"].contains(expected) ? "READY" : "DB_NOT_UPDATED")
    }
}
struct R1ThreatCoverage: Decodable {
    let listed_entries: Int, checked_files: Int, uninspectable_files: Int, directories: Int
    let bytes_hashed: Int, read_budget_reserved: Int
    let complete: Bool
}
struct R1ThreatEntry: Decodable {
    let entry_index: Int, path: String, source_role: String, status: String
    let sha256: String?
}
struct R1ThreatMatch: Decodable { let entry_index: Int; let sha256: String }
struct R1ThreatUnknown: Decodable { let code: String; let entry_index: Int? }
struct R1ThreatIntelligence: Decodable {
    let schema: String, status: String
    let database: R1ThreatDatabase
    let coverage: R1ThreatCoverage
    let entries: [R1ThreatEntry], matches: [R1ThreatMatch], unknown_conditions: [R1ThreatUnknown]
    let safety_proven: Bool, authorizes_actions: Bool

    private func hex(_ value: String) -> Bool {
        value.utf8.count == 64 && value.unicodeScalars.allSatisfy {
            (48...57).contains($0.value) || (97...102).contains($0.value)
        }
    }
    var valid: Bool {
        guard schema == "orchard-ti-inspection/1", !safety_proven, !authorizes_actions,
              ["KNOWN_HASH_MATCH", "NO_MATCH_IN_COVERED_DB", "DB_NOT_UPDATED", "UNINSPECTABLE"].contains(status),
              ["READY", "DB_NOT_UPDATED"].contains(database.status), database.policyValid, database.metadata != nil,
              coverage.listed_entries >= 0, coverage.listed_entries <= 128,
              entries.count <= 128, matches.count <= 128, unknown_conditions.count <= 512,
              coverage.checked_files >= 0, coverage.checked_files <= entries.count,
              coverage.uninspectable_files >= 0, coverage.directories >= 0,
              coverage.bytes_hashed >= 0, coverage.bytes_hashed <= 8_388_608,
              coverage.read_budget_reserved >= 0, coverage.read_budget_reserved <= 8_388_608,
              entries.allSatisfy({ $0.entry_index >= 0 && $0.entry_index < 128 &&
                  $0.source_role == "UNTRUSTED_ARCHIVE_DATA" && $0.path.utf8.count <= 512 &&
                  ($0.sha256 == nil || hex($0.sha256!)) }),
              matches.allSatisfy({ $0.entry_index >= 0 && $0.entry_index < 128 && hex($0.sha256) })
        else { return false }
        if let meta = database.metadata {
            guard meta.data_kind == "MALWAREBAZAAR_REAL_SHA_BOUNDED_SUBSET", meta.provider == "abuse.ch-malwarebazaar",
                  meta.fields == ["sha256"], meta.record_count == 100000, meta.deletion_revision == 0,
                  meta.source_url == "https://bazaar.abuse.ch/export/",
                  meta.coverage == "Retained Recent union deterministic bounded Full subset; not complete corpus or newest 100000",
                  meta.license_basis == "ST7343382_FREE_OSS_NO_REVENUE_PRIVATE_100K_INTEGRATION_PUBLIC_HOLD",
                  meta.updated_at_utc == "2026-11-14T03:24:27Z",
                  meta.attribution == "Malware hash data courtesy of abuse.ch MalwareBazaar (https://bazaar.abuse.ch), provided in collaboration with Spamhaus Technology. Used with permission. No match does not mean a file is safe.",
                  database.snapshot_sha256 == "c6ae23abcddcab9176a12514a11d4d0a094dfe4894e494fbf9a33d5fc4b4a2ff"
            else { return false }
        }
        guard Set(entries.map { $0.entry_index }).count == entries.count,
              matches.allSatisfy({ match in entries.contains(where: {
                  $0.entry_index == match.entry_index && $0.sha256 == match.sha256 && $0.status == "KNOWN_HASH_MATCH"
              }) }) else { return false }
        if status == "KNOWN_HASH_MATCH" { return !matches.isEmpty }
        guard matches.isEmpty else { return false }
        if status == "NO_MATCH_IN_COVERED_DB" { return permitsReview }
        if status == "DB_NOT_UPDATED" { return database.status == "DB_NOT_UPDATED" }
        return !coverage.complete
    }
    var permitsReview: Bool {
        status == "NO_MATCH_IN_COVERED_DB" && database.status == "READY" && ["DB_READY", "DB_STALE"].contains(database.reason) &&
        database.metadata != nil && coverage.complete && coverage.checked_files > 0 &&
        coverage.uninspectable_files == 0 && matches.isEmpty && unknown_conditions.isEmpty &&
        entries.count == coverage.listed_entries &&
        coverage.checked_files + coverage.directories == entries.count &&
        Set(entries.map { $0.entry_index }).count == entries.count &&
        entries.allSatisfy({ ($0.status == "NO_MATCH_IN_COVERED_DB" && $0.sha256 != nil) ||
                            ($0.status == "DIRECTORY_NOT_APPLICABLE" && $0.sha256 == nil) })
    }
    private func visible(_ value: String) -> String {
        String(value.unicodeScalars.prefix(512).map { scalar in
            let code = scalar.value
            return code < 32 || code == 127 || (0x202A...0x202E).contains(code) || (0x2066...0x2069).contains(code)
                ? String(format: "\\u{%04X}", code) : String(scalar)
        }.joined())
    }
    var displayLines: [String] {
        let label: String
        switch status {
        case "KNOWN_HASH_MATCH": label = "収録済みの実SHAに一致（安全性は判定しません）"
        case "NO_MATCH_IN_COVERED_DB": label = "対象DB内に一致なし（安全を意味しません）"
        case "DB_NOT_UPDATED": label = "DBの更新未確認。不一致を判定できません"
        default: label = "照合を完了できない項目があります"
        }
        let mode = database.verification_mode
        var lines = [mode == "LIVE" ? "通常検査：Macの現在時刻で判定" :
            mode == "AFTER_25H_SIMULATION" ? "【検証】25時間超の時計シミュレーション。実際の現在時刻・DBは変更していません。" :
            "【検証】更新失敗の表示シミュレーション。実際の取得失敗ではありません。",
            "ZIPのSHA照合: \(label)",
            "ZIP照合範囲: \(coverage.checked_files)ファイル / 検査不能 \(coverage.uninspectable_files) / 一致 \(matches.count)"]
        switch database.reason {
        case "DB_READY": lines += ["DB状態: 保存済み倉庫を照合。25時間以内（経過時間は参考情報）"]
        case "DB_STALE": lines += ["DB状態: 25時間超（参考情報）。保存済み倉庫内の一致・未一致を照合します。"]
        case "UPDATE_FAILED": lines += ["DB状態: 更新失敗。既知一致は保持し、不一致は保留します。"]
        default: lines += ["DB状態: 時刻を確認できません。不一致は保留します。"]
        }
        if let meta = database.metadata {
            lines += ["供給元の生成UTC: \(visible(meta.updated_at_utc))",
                "取得UTC: \(visible(database.retrieved_at_utc)) / 収録SHA \(meta.record_count)件",
                "直近取得結果: \(database.update_attempt_status == "SUCCESS" ? "成功" : "失敗") / \(visible(database.update_attempt_at_utc))",
                "保持Recent分の提供元宣言範囲: \(visible(database.declared_coverage_start_utc)) 〜 \(visible(database.declared_coverage_end_utc))（48時間）",
                "Full snapshot生成UTC: \(visible(database.Full_source_generated_at_utc))",
                "Full取得UTC: \(visible(database.Full_retrieved_at_utc))",
                "倉庫構成: Recent保持1,048件＋限定Full98,952件＝100,000件。順序に新旧の意味はありません。",
                "限定収録：全期間の完全収録・最新10万件・広範な検出は保証しません。",
                "次回確認目安UTC: \(visible(database.next_check_due_utc))（1日1回）。自動更新は無効です。",
                "出典: \(visible(meta.source_url))", visible(meta.attribution)]
        }
        lines += ["", "倉庫内の既存SHA照合（自己確認）: \(database.warehouse_self_check.matched)/\(database.warehouse_self_check.checked)件 一致",
            "自己確認はZIPの陽性検出ではありません。実SHA値は表示・出力しません。",
            "一致なしは安全・開封・実行の許可ではありません。"]
        return lines
    }
}
