import Foundation
import CryptoKit

struct MonitorImpactReview: Decodable {
    enum Coverage: String, Decodable { case described = "DESCRIBED", partial = "PARTIAL", unverified = "UNVERIFIED" }
    enum Scope: String, Decodable { case expanded = "EXPANDED", same = "NO_EXPANSION", unknown = "UNKNOWN" }
    enum FutureUse: String, Decodable { case possible = "POSSIBLE", none = "NO_NEW_DIRECTIVE", unknown = "UNKNOWN" }
    enum DestinationRelation: String, Decodable {
        case added = "ADDED", changed = "CHANGED", unchanged = "UNCHANGED", unlinked = "UNLINKED", dynamic = "DYNAMIC"
    }
    enum LookupStatus: String, Decodable { case match = "MATCH", noMatch = "NO_MATCH", unverified = "UNVERIFIED" }
    enum MatchScope: String, Decodable { case url = "EXACT_URL", host = "EXACT_HOST" }
    enum FeedState: String, Decodable { case ready = "READY", missing = "MISSING", stale = "STALE", invalid = "INVALID" }
    enum FeedSource: String, Decodable { case urlhaus = "URLHAUS", synthetic = "SYNTHETIC" }
    enum Side: String, Decodable { case before = "BEFORE", after = "AFTER" }
    enum Rule: String, Decodable, CaseIterable {
        case quoted = "QUOTED", text = "TEXT_ONLY", procedure = "PROCEDURE", restriction = "RESTRICTION"
        case expansion = "SCOPE_CHANGE", transfer = "EXTERNAL_TRANSFER", sensitive = "SENSITIVE_DATA"
        case destructive = "DESTRUCTIVE", unknown = "UNKNOWN"
        case approvalBypass = "APPROVAL_BYPASS", falseApproval = "FALSE_APPROVAL"
        case falseReviewCompletion = "FALSE_REVIEW_COMPLETION"
    }
    enum Limit: String, Decodable {
        case analysis = "ANALYSIS_LIMIT", evidence = "EVIDENCE_LIMIT", destinations = "DESTINATION_LIMIT"
    }

    struct Evidence: Decodable {
        let side: Side
        let line: Int
        let original: String
        let actions: [Rule]
        let level: Int?
        let persistent: Bool
        let skips_approval: Bool
        let irreversible: Bool
        let approval_owner: String?
    }
    struct Lookup: Decodable {
        let status: LookupStatus
        let scopes: [MatchScope]
        let matches: [MatchScope]
    }
    struct Destination: Decodable {
        let line: Int
        let host: String?
        let relation: DestinationRelation
        let previous_hosts: [String]
        let lookup: Lookup
    }
    struct Intelligence: Decodable {
        let source: FeedSource
        let state: FeedState
        let retrieved_at_utc: String?
    }

    let version: Int
    let kind: String
    let coverage: Coverage
    let scope: Scope
    let level: Int?
    let future_use: FutureUse
    let evidence: [Evidence]
    let destinations: [Destination]
    let unknown_lines: Int
    let limits: [Limit]
    let intelligence: Intelligence
    let intent: String

    static func decode(_ raw: Any?, kind: String) -> Self? {
        guard let raw, JSONSerialization.isValidJSONObject(raw),
              let bytes = try? JSONSerialization.data(withJSONObject: raw), bytes.count <= 384 * 1024,
              let model = try? JSONDecoder().decode(Self.self, from: bytes),
              model.version == 1, model.kind == kind, model.intent == "NOT_AVAILABLE",
              (0...512).contains(model.unknown_lines),
              model.evidence.count <= 24, model.destinations.count <= 32, model.limits.count <= 3,
              validLevel(model.level), model.evidence.allSatisfy({
                  (1...512).contains($0.line) && $0.original.utf8.count <= 64 * 1024 &&
                  !$0.actions.isEmpty && $0.actions.count <= Rule.allCases.count && validLevel($0.level)
                  && ($0.approval_owner.map(validApprover) ?? true)
                  && ($0.approval_owner == nil || ($0.actions.contains(.approvalBypass) && $0.skips_approval))
              }), model.destinations.allSatisfy({ validDestination($0, feed: model.intelligence.state) }),
              model.intelligence.retrieved_at_utc.map({
                  $0.utf8.count <= 25 && ISO8601DateFormatter().date(from: $0) != nil
              }) ?? (model.intelligence.state != .ready && model.intelligence.state != .stale),
              model.coverage != .unverified || (model.level == nil && model.evidence.isEmpty && model.destinations.isEmpty) else {
            return nil
        }
        return model
    }

    private static func validLevel(_ level: Int?) -> Bool { level.map { (1...5).contains($0) } ?? true }

    private static func validApprover(_ name: String) -> Bool {
        let characters = CharacterSet.letters.union(.decimalDigits).union(CharacterSet(charactersIn: "_.-"))
        return (1...48).contains(name.utf8.count) && name.unicodeScalars.allSatisfy(characters.contains)
    }

    private static func validHost(_ host: String) -> Bool {
        (1...253).contains(host.utf8.count) && host.utf8.allSatisfy {
            (48...57).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 || $0 == 58
        }
    }

    private static func validDestination(_ value: Destination, feed: FeedState) -> Bool {
        guard (1...512).contains(value.line),
              value.host.map(validHost) ?? (value.relation == .dynamic),
              value.previous_hosts.count <= 128, value.previous_hosts.allSatisfy(validHost),
              value.lookup.scopes.count <= 2, value.lookup.matches.count <= 2,
              value.lookup.matches.allSatisfy(value.lookup.scopes.contains) else { return false }
        switch value.lookup.status {
        case .match: return feed == .ready && value.host != nil && !value.lookup.matches.isEmpty
        case .noMatch: return feed == .ready && value.host != nil && !value.lookup.scopes.isEmpty && value.lookup.matches.isEmpty
        case .unverified: return value.lookup.scopes.isEmpty && value.lookup.matches.isEmpty
        }
    }
}

struct InstructionChangeSummary {
    let level: Int?
    let levelLimited: Bool
    let changes: [String]
    let highImpact: Bool
    let impact: String
    let notes: [String]

    init(review: MonitorImpactReview?, japanese: Bool) {
        func text(_ ja: String, _ en: String) -> String { japanese ? ja : en }
        let after = (review?.evidence ?? []).filter { $0.side == .after }.sorted {
            let left = $0.level ?? 0, right = $1.level ?? 0
            return left == right ? $0.line < $1.line : left > right
        }
        let severe = after.filter { ($0.level ?? 0) >= 4 }
        level = review?.level
        levelLimited = review?.coverage != .described && level.map { $0 < 5 } == true
        highImpact = (level ?? 0) >= 4 || !severe.isEmpty
        let severeActions = severe.flatMap(\.actions)
        let approvers = Set(severe.filter { $0.actions.contains(.approvalBypass) }.map(\.approval_owner))
        let approver = approvers.count == 1 ? approvers.first ?? nil : nil
        let requests = Self.highImpactActions(severeActions, japanese: japanese, approver: approver)
        if highImpact {
            impact = requests.isEmpty ? text("高影響の要求あり", "High-impact request found")
                : text(requests.joined(separator: "・") + "を求める指示", "Requests " + requests.joined(separator: ", "))
        } else if level == nil {
            impact = text("変更後の指示の意味を確定できません。", "The requested action could not be determined.")
        } else {
            impact = text("確認範囲で高影響の要求なし", "No high-impact request found")
        }

        var addedLabels = Set<String>(), removedLabels = Set<String>()
        var observed: [String] = []
        for row in after {
            guard let label = Self.actionLabel(row, japanese: japanese), addedLabels.insert(label).inserted else { continue }
            if (row.level ?? 0) >= 4 && !Self.highImpactActions(row.actions, japanese: japanese).isEmpty { continue }
            if review?.kind == "ADDED" {
                observed.append(text("\(label)を追加", "Added \(label)"))
            } else {
                observed.append(text("変更後に\(label)を記載", "Changed text includes \(label)"))
            }
        }
        for row in review?.evidence ?? [] where row.side == .before {
            guard let label = Self.actionLabel(row, japanese: japanese),
                  !addedLabels.contains(label), removedLabels.insert(label).inserted else { continue }
            observed.append(text("\(label)を変更箇所から削除", "Removed \(label) from the changed text"))
        }
        if observed.isEmpty && requests.isEmpty {
            if review?.coverage == .described && !highImpact {
                observed = [text("新しい行動指示は確認されませんでした", "No new action was found in the assessed change")]
            } else {
                observed = [text("変更を検出しました。行動の内容は未確認です", "Change detected. The requested action is unverified")]
            }
        }
        changes = Array(observed.prefix(3))

        var flags: [String] = []
        if severe.contains(where: \.persistent) { flags.append(text("継続適用", "recurring use")) }
        if severe.contains(where: \.skips_approval) && !severeActions.contains(.approvalBypass) {
            flags.append(text("承認の省略", "skipping approval"))
        }
        if severe.contains(where: \.irreversible) { flags.append(text("復元困難な処理", "hard-to-reverse actions")) }
        var attention: [String] = []
        if !flags.isEmpty {
            attention.append(text(flags.joined(separator: "・") + "の記載あり。", "The text specifies " + flags.joined(separator: ", ") + "."))
        }
        if severeActions.contains(.approvalBypass) || severeActions.contains(.falseApproval) {
            attention.append(text("実際の承認を経ずに変更が進むおそれがあります。",
                                  "Unapproved changes could proceed."))
        }
        if severeActions.contains(.falseReviewCompletion) {
            attention.append(text("未確認のレビューが完了扱いになるおそれがあります。",
                                  "An unfinished review could be treated as complete."))
        }
        if review?.scope == .expanded { attention.append(text("指示上の行動範囲が拡大。", "The requested scope expanded.")) }
        if let review {
            if review.limits.contains(.analysis) {
                attention.append(text("分析上限により影響を確認できません。", "The assessment exceeded its analysis limit."))
            } else if review.coverage == .unverified {
                attention.append(text("比較に必要な原文・記録は未確認です。", "The text or comparison records are unverified."))
            } else if level != nil && (review.coverage == .partial || review.unknown_lines > 0) {
                attention.append(text("変更後の指示に判定できない部分があります。", "Some changed instructions remain undetermined."))
            }
            let matchedDestination = review.destinations.contains(where: { $0.lookup.status == .match })
            if matchedDestination {
                attention.append(text("送信先候補が既知悪性情報に一致。", "A destination candidate matches known-malicious intelligence."))
            } else if review.destinations.contains(where: { $0.lookup.status == .unverified }) {
                attention.append(text("未照合の送信先候補があります。", "Some destination candidates are unchecked."))
            }
            if review.scope == .unknown && review.coverage == .described {
                attention.append(text("指示上の行動範囲の変化は不明です。", "The change in requested scope is undetermined."))
            }
        } else {
            attention.append(text("変更の分類結果は未確認です。", "The change assessment is unverified."))
        }
        notes = attention
    }

    private static func highImpactActions(_ actions: [MonitorImpactReview.Rule], japanese: Bool, approver: String? = nil) -> [String] {
        let bypass: String
        if let approver {
            bypass = japanese ? "\(approver)の承認を省くこと" : "bypassing \(approver)’s approval"
        } else {
            bypass = japanese ? "承認を省くこと" : "bypassing approval"
        }
        let categories: [(MonitorImpactReview.Rule, String)] = [
            (.approvalBypass, bypass),
            (.falseApproval, japanese ? "変更を承認済みとして扱うこと" : "treating changes as already approved"),
            (.falseReviewCompletion, japanese ? "レビューを完了扱いにすること" : "treating the review as complete"),
            (.transfer, japanese ? "外部送信" : "external transfer"),
            (.destructive, japanese ? "削除・消去" : "deletion or erasure"),
            (.sensitive, japanese ? "機密情報の取扱い" : "handling sensitive data")
        ]
        return categories.filter { actions.contains($0.0) }.map(\.1)
    }

    private static func actionLabel(_ row: MonitorImpactReview.Evidence, japanese: Bool) -> String? {
        func text(_ ja: String, _ en: String) -> String { japanese ? ja : en }
        guard !row.actions.contains(.unknown) else { return nil }
        let requirements = highImpactActions(row.actions, japanese: japanese, approver: row.approval_owner)
        if !requirements.isEmpty {
            return text(requirements.joined(separator: "・") + "を求める指示",
                        "instructions requesting " + requirements.joined(separator: ", "))
        }
        if row.actions.contains(.expansion) {
            return text("行動範囲や既存の制約の変更を求める指示", "instructions to change scope or constraints")
        }
        if row.actions.contains(.restriction) {
            return text("行動を制限する指示", "a restriction on actions")
        }
        if row.actions.contains(.procedure) {
            // Only paraphrase complete phrases already classified as procedures.
            let wording = row.original.precomposedStringWithCanonicalMapping
                .replacingOccurrences(of: #"^\s*(?:[-*+]\s+|\d+[.)]\s+)"#, with: "", options: .regularExpression)
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: ".。")).lowercased()
            switch wording {
            case "keep a local audit log", "ローカルに監査ログを残すこと":
                return text("ローカルに監査ログを残す手順", "a procedure to keep a local audit log")
            case "follow existing instructions", "既存の指示に従うこと":
                return text("既存の指示に従う手順", "a procedure to follow existing instructions")
            case "run tests before committing", "run the tests before committing", "run the test suite before committing",
                 "コミット前にテストを実行すること":
                return text("コミット前にテストを実行する手順", "a procedure to run tests before committing")
            case "run tests before updating documentation", "run the tests before updating documentation", "文書更新前にテストを実行すること":
                return text("文書更新前にテストを実行する手順", "a procedure to run tests before updating documentation")
            case "run tests", "run the tests", "run the test suite", "テストを実行すること":
                return text("テストを実行する手順", "a procedure to run tests")
            case "review the documentation", "review the docs", "文書を確認すること":
                return text("文書を確認する手順", "a procedure to review documentation")
            case "run lint", "run the linter", "run lint before committing", "lintを実行すること":
                return text("静的チェックを実行する手順", "a procedure to run a linter")
            default:
                return text("作業手順", "a work procedure")
            }
        }
        if row.actions.contains(.quoted) { return text("引用・例の記載", "a quotation or example") }
        if row.actions.contains(.text) { return text("表記・説明", "wording or formatting") }
        return nil
    }
}

enum OrchardZipLimits {
    static let legacyFormat = "orchard-c-static-zip/1.0"
    static let previousFormat = "orchard-c-static-zip/1.1"
    static let scopeDetailFormat = "orchard-c-static-zip/1.2"
    static let currentFormat = "orchard-c-static-zip/1.3"
    static let previousArchiveBytes = 32 * 1024 * 1024
    static let archiveMiB = 72
    static let archiveBytes = archiveMiB * 1024 * 1024
    static let entries = 1_024
    static let totalMemberBytes = 64 * 1024 * 1024
    static let pathBytes = 512
    static let textBytes = 32 * 1024 * 1024
    static let thoroughEntries = 4_096
    static let thoroughMemberBytes = 128 * 1024 * 1024
    static let thoroughTextBytes = 64 * 1024 * 1024
    static let thoroughHostSeconds = 28.0
    static let stdoutBytes = 3 * 1024 * 1024
    static let receiptBytes = 12 * 1024 * 1024
}

// A3 consumes saved A2 evidence. ZIP text is data and never supplies an action.
private struct R1Input: Decodable { let bytes: Int; let sha256: String }
private struct R1Coverage: Decodable {
    let listed_entries: Int, text_files_read: Int, text_bytes_read: Int
    let hash_only_files: Int?, uninspected_files: Int?, directories: Int?
}
private struct R1Finding: Decodable {
    let category: String, path: String, matched_text: String, source_role: String
    let line: Int, entry_index: Int, start_char: Int, end_char: Int
    let nested_member_path: String?
}

struct R1NestedZipScope: Decodable {
    let entry_index: Int
    let kind: String, status: String
    let entries: Int, text_files_read: Int, text_bytes_read: Int, ordinary_out_of_scope: Int
    let reasons: [String: Int]
    let child_report: Bool?

    var complete: Bool { status == "COMPLETE" }
    var archiveFormatUnconfirmed: Bool { kind != "OTHER_ARCHIVE" && reasons["NESTED_FORMAT_UNSUPPORTED"] != nil }

    func valid(outerEntries: Int, maxEntries: Int, maxTextBytes: Int) -> Bool {
        (0..<outerEntries).contains(entry_index) && ["ZIP", "WHEEL", "TAR", "GZIP", "OTHER_ARCHIVE", "CANDIDATE"].contains(kind) &&
        ["COMPLETE", "PARTIAL", "UNREAD"].contains(status) && (0...maxEntries).contains(entries) &&
        (0...entries).contains(text_files_read) && (0...entries).contains(ordinary_out_of_scope) &&
        (text_files_read...maxTextBytes).contains(text_bytes_read) &&
        text_files_read + ordinary_out_of_scope <= entries &&
        (status != "UNREAD" || entries == 0) && (status != "PARTIAL" || entries > 0) &&
        (complete == reasons.isEmpty) && R1ZipScopeDetail.reasonsValid(reasons)
    }
}

struct R1ZipScopeDetail: Decodable {
    let structure_status: String, outer_text_status: String
    let ordinary_out_of_scope: Int, outer_unresolved: Int
    let nested: [R1NestedZipScope]
    let blocking_reasons: [String: Int]

    var nestedRemaining: Int { nested.filter { !$0.complete }.count }
    var nestedTextFiles: Int { nested.reduce(0) { $0 + $1.text_files_read } }
    var detailedBlockingReasons: [String: Int] {
        var reasons = blocking_reasons
        if !nested.isEmpty { reasons.removeValue(forKey: "NESTED_CONTENT_UNRESOLVED") }
        // Pre-check refusals already appear in the outer reasons.
        for item in nested {
            let legacyChild = item.kind != "CANDIDATE" && item.reasons["NESTED_FORMAT_UNSUPPORTED"] == nil &&
                item.reasons["NESTED_ARCHIVE_SIZE_LIMIT"] == nil
            if item.child_report ?? legacyChild { reasons.merge(item.reasons, uniquingKeysWith: +) }
        }
        return reasons
    }

    static func reasonsValid(_ reasons: [String: Int]) -> Bool {
        reasons.count <= 128 && reasons.allSatisfy { code, count in
            (1...32768).contains(count) && (1...96).contains(code.utf8.count) &&
            code.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) ||
                                  (97...122).contains($0) || $0 == 95 }
        }
    }

    static func isStructuralAnomaly(_ code: String) -> Bool {
        let prefixes = ["MALFORMED_", "UNSAFE_OR_", "DUPLICATE_OR_", "LOCAL_HEADER_", "LOCAL_METADATA_", "LOCAL_NAME_",
                        "MEMBER_SPAN_", "MEMBER_STREAM_", "MEMBER_LENGTH_", "STORED_SIZE_",
                        "CONTAINER_LAYOUT_", "ZIP_UNREADABLE_", "DIRECTORY_PAYLOAD_", "CENTRAL_DIRECTORY_COUNT_",
                        "TAR_STRUCTURE_", "GZIP_STRUCTURE_", "EXPANSION_RATIO_", "NESTED_EXPANSION_RATIO_"]
        return code == "ZIP_LINK_TARGET_EXTERNAL" || code == "ZIP_LINK_PATH_CONFLICT"
            || prefixes.contains { code.hasPrefix($0) }
    }

    fileprivate func valid(coverage: R1Coverage, status: String, maxEntries: Int, maxTextBytes: Int) -> Bool {
        let count = coverage.listed_entries
        guard ["CHECKED", "INCOMPLETE"].contains(structure_status),
              ["CHECKED", "INCOMPLETE", "NO_TEXT_IN_SCOPE"].contains(outer_text_status),
              (0...count).contains(ordinary_out_of_scope), (0...count).contains(outer_unresolved),
              nested.count <= count, nested.allSatisfy({ $0.valid(outerEntries: count, maxEntries: maxEntries,
                                                                  maxTextBytes: maxTextBytes) }),
              Set(nested.map(\.entry_index)).count == nested.count,
              Self.reasonsValid(blocking_reasons)
        else { return false }
        let nestedBytes = nested.reduce(0) { $0 + $1.text_bytes_read }
        let nestedEntries = nested.reduce(0) { $0 + $1.entries }
        return count + nestedEntries <= maxEntries &&
            nestedBytes + coverage.text_bytes_read <= maxTextBytes &&
            ordinary_out_of_scope + (nested.count - nestedRemaining) == coverage.hash_only_files &&
            outer_unresolved + nestedRemaining == coverage.uninspected_files &&
            ((status == "UNKNOWN") == !blocking_reasons.isEmpty) &&
            (outer_text_status == "INCOMPLETE" || outer_unresolved == 0) &&
            (outer_text_status != "NO_TEXT_IN_SCOPE" || coverage.text_files_read == 0)
    }
}
private struct R1CharacterWarning: Decodable {
    let codepoint: String
    let line: Int, column: Int

    var valid: Bool {
        guard line > 0, column > 0, codepoint.hasPrefix("U+") else { return false }
        let digits = codepoint.utf8.dropFirst(2)
        return (4...6).contains(digits.count) && digits.allSatisfy { (48...57).contains($0) || (65...70).contains($0) }
            && Int(codepoint.dropFirst(2), radix: 16).flatMap { Unicode.Scalar($0) } != nil
    }
}

private struct R1Unknown: Decodable {
    let code: String
    let entry_index: Int?
    let character_warnings: [R1CharacterWarning]?
    let character_evidence_truncated: Bool?
    let instruction_scan_completed: Bool?

    func characterEvidenceValid(entries: Int) -> Bool {
        guard let warnings = character_warnings else {
            return character_evidence_truncated == nil && instruction_scan_completed != true
        }
        guard code == "TEXT_CONTROL_OR_FORMAT_CHARACTER", let index = entry_index,
              (0..<entries).contains(index), character_evidence_truncated != nil else { return false }
        return warnings.allSatisfy(\.valid) &&
            (instruction_scan_completed != true || (character_evidence_truncated == false &&
                !warnings.isEmpty && warnings.allSatisfy { $0.codepoint == "U+0008" }))
    }
}
enum R1ZipInspectionPresentation: String, Decodable {
    case detected = "DETECTED"
    case checkFailed = "CHECK_FAILED"
    case partial = "PARTIAL"
    case outOfScope = "OUT_OF_SCOPE_FORMATS"
    case complete = "COMPLETE"
}

enum R1InstructionScopeStatus: String, Decodable {
    case noFindings = "NO_FINDINGS"
    case detected = "DETECTED"
    case incomplete = "INCOMPLETE"
    case noTargets = "NO_TARGETS"

    var complete: Bool { self == .noFindings || self == .noTargets }
}

enum R1ZipInspectionGate: String, Decodable {
    case cap = "CAP"
    case hold = "HOLD"
}

struct R1InstructionScopeItem: Decodable {
    enum Disposition: String, Decodable {
        case excluded = "OUT_OF_SCOPE"
        case unread = "UNREAD"
    }
    let entry_index: Int
    let nested_entry_index: Int?
    let nested_member_path: String?
    let disposition: Disposition
    let reasons: [String: Int]
}

struct R1InstructionReference: Decodable {
    let source_entry_index: Int, target_entry_index: Int
    let source_nested_entry_index: Int?, target_nested_entry_index: Int?
    let source_nested_member_path: String?
    let line: Int
    let indirect: Bool
}

struct R1InstructionCheckedMember: Decodable {
    let entry_index: Int
    let nested_entry_index: Int?
    let nested_member_path: String?
}

struct R1InstructionScope: Decodable {
    let status: R1InstructionScopeStatus
    let checked_files: Int
    let archive_reasons: [String: Int]
    let items: [R1InstructionScopeItem]
    let checked_members: [R1InstructionCheckedMember]?
    let references: [R1InstructionReference]?
    let reference_check_complete: Bool?

    var excludedCount: Int { items.filter { $0.disposition == .excluded }.count }
    var unreadCount: Int { items.count - excludedCount }
    var hasUnread: Bool { !archive_reasons.isEmpty || unreadCount > 0 }
    var unreadReasons: [String: Int] {
        var reasons = archive_reasons
        for item in items where item.disposition == .unread {
            reasons.merge(item.reasons, uniquingKeysWith: +)
        }
        return reasons
    }

    fileprivate func valid(archive: R1ZipScopeDetail, outerChecked: Int, hasFindings: Bool,
                           threat: R1ThreatIntelligence, maxEntries: Int) -> Bool {
        let expectedStatus: R1InstructionScopeStatus = hasFindings ? .detected :
            hasUnread ? .incomplete : checked_files > 0 ? .noFindings : .noTargets
        guard status == expectedStatus, checked_files == outerChecked + archive.nestedTextFiles,
              checked_files + items.count <= maxEntries,
              R1ZipScopeDetail.reasonsValid(archive_reasons) else { return false }
        let inner = Dictionary(uniqueKeysWithValues: archive.nested.map { ($0.entry_index, $0) })
        let hashed = Set(threat.entries.filter { $0.sha256 != nil }.map(\.entry_index))
        var seen = Set<String>()
        var reasons = archive_reasons
        var ordinary = 0
        for item in items {
            let index = item.entry_index
            guard (0..<threat.entries.count).contains(index),
                  !item.reasons.isEmpty, R1ZipScopeDetail.reasonsValid(item.reasons) else { return false }
            if let nestedIndex = item.nested_entry_index {
                guard let innerCount = inner[index]?.entries, (0..<innerCount).contains(nestedIndex),
                      let path = item.nested_member_path, !path.isEmpty, path.utf8.count <= OrchardZipLimits.pathBytes,
                      seen.insert("\(index)/\(nestedIndex)").inserted else { return false }
            } else {
                guard item.nested_member_path == nil, seen.insert("\(index)").inserted else { return false }
            }
            if item.disposition == .excluded {
                guard let (code, count) = item.reasons.first, item.reasons.count == 1, count == 1,
                      hashed.contains(index) || Self.metadataOnlyExclusions.contains(code) else { return false }
                if code == "TEXT_BODY_NOT_APPLICABLE" || code == "INTERNAL_LINK_REFERENCE" {
                    ordinary += 1
                    continue
                }
                guard Self.formatExclusions.contains(code) ||
                        (code == "NESTED_FORMAT_UNSUPPORTED" && inner[index]?.kind == "OTHER_ARCHIVE" &&
                         item.nested_entry_index == nil) else { return false }
            }
            reasons.merge(item.reasons, uniquingKeysWith: +)
        }
        let expectedOrdinary = archive.ordinary_out_of_scope + archive.nested.reduce(0) { $0 + $1.ordinary_out_of_scope }
        return ordinary == expectedOrdinary && reasons == archive.detailedBlockingReasons &&
            validCheckedMembers(inner: inner, hashed: hashed, nonText: seen)
    }

    private func validCheckedMembers(inner: [Int: R1NestedZipScope], hashed: Set<Int>, nonText: Set<String>) -> Bool {
        guard let checked_members else { return references == nil && reference_check_complete == nil }
        guard checked_members.count == checked_files else { return false }
        var checked = [String: R1InstructionCheckedMember]()
        for row in checked_members {
            let id = Self.memberID(row.entry_index, row.nested_entry_index)
            guard hashed.contains(row.entry_index), !nonText.contains(id), checked[id] == nil else { return false }
            if let nested = row.nested_entry_index {
                guard let rows = inner[row.entry_index]?.entries, (0..<rows).contains(nested),
                      let path = row.nested_member_path, !path.isEmpty, path.utf8.count <= OrchardZipLimits.pathBytes
                else { return false }
            } else if row.nested_member_path != nil || inner[row.entry_index] != nil {
                return false
            }
            checked[id] = row
        }
        guard let references else { return reference_check_complete == nil }
        guard reference_check_complete != nil, references.count <= checked_files else { return false }
        let unread = Set(items.filter { $0.disposition == .unread }.map {
            Self.memberID($0.entry_index, $0.nested_entry_index)
        })
        var seen = Set<String>()
        return references.allSatisfy { ref in
            let source = Self.memberID(ref.source_entry_index, ref.source_nested_entry_index)
            let target = Self.memberID(ref.target_entry_index, ref.target_nested_entry_index)
            return (1...OrchardZipLimits.textBytes).contains(ref.line) && seen.insert(source).inserted &&
                checked[source].map { $0.nested_member_path == ref.source_nested_member_path } == true &&
                unread.contains(target)
        }
    }

    private static func memberID(_ outer: Int, _ nested: Int?) -> String {
        nested.map { "\(outer)/\($0)" } ?? "\(outer)"
    }

    fileprivate static let metadataOnlyExclusions: Set<String> = [
        "ENCRYPTED_ENTRY_UNSUPPORTED", "LINK_OR_SPECIAL_FILE_UNSUPPORTED",
        "ZIP_LINK_TARGET_INVALID", "ZIP_LINK_TARGET_UNRESOLVED", "ZIP_LINK_TARGET_CYCLE"
    ]
    fileprivate static let formatExclusions = metadataOnlyExclusions.union([
        "NON_PLAIN_TEXT_DOCUMENT_UNINSPECTED", "EXECUTABLE_BODY_UNINSPECTED",
        "SQLITE_BODY_UNINSPECTED", "OPAQUE_BINARY_UNINSPECTED", "UNSUPPORTED_ARCHIVE_BODY_OUT_OF_SCOPE"
    ])
}

private struct R1Report: Decodable {
    let format: String, inspection_status: String, prompt_injection: String, gate: String
    let input: R1Input
    let findings: [R1Finding], unknown_conditions: [R1Unknown]
    let coverage: R1Coverage, limits: [String: Int]
    let scope: String, limitations: [String]
    let safety_proven: Bool, authorizes_actions: Bool
    let threat_intelligence: R1ThreatIntelligence?
    let scope_detail: R1ZipScopeDetail?
    let inspection_presentation: R1ZipInspectionPresentation?
    let instruction_scope: R1InstructionScope?
    let inspection_gate: R1ZipInspectionGate?
    let inspection_profile: String?
    let finding_details_truncated: Bool?

    func presentationValid(threat: R1ThreatIntelligence) -> Bool {
        guard let presentation = inspection_presentation else { return true }
        guard let scope = scope_detail else { return false }
        let detected = prompt_injection == "DETECTED" || !findings.isEmpty || !threat.matches.isEmpty
        if detected { return presentation == .detected }

        let shaChecked = threat.permitsReview || threat.status == "NO_ITEMS_IN_SCOPE"
        let complete = inspection_status == "COMPLETE" && gate == "CAP" && shaChecked
        switch presentation {
        case .detected: return false
        case .complete: return complete
        case .partial, .checkFailed: return !complete
        case .outOfScope:
            let formatCodes = R1InstructionScope.formatExclusions.union(["NESTED_FORMAT_UNSUPPORTED"])
            let reasons = Set(scope.blocking_reasons.keys).subtracting(["NESTED_CONTENT_UNRESOLVED"])
                .union(scope.nested.flatMap { $0.reasons.keys })
            return inspection_status == "UNKNOWN" && scope.structure_status == "CHECKED" && shaChecked &&
                !reasons.isEmpty && reasons.isSubset(of: formatCodes) &&
                (scope.blocking_reasons["NESTED_CONTENT_UNRESOLVED"] == nil || !scope.nested.isEmpty) &&
                !scope.nested.contains(where: \.archiveFormatUnconfirmed)
        }
    }
}
private struct R1WorkerReceipt: Decodable {
    let json_status: String, parent_gate: String
    let stop_reason: String?
    let exit_code: Int?
    let start_identity_valid: Bool, waitpid_reaped: Bool, all_created_pipe_fds_closed: Bool
    let authorizes_actions: Bool
    let input_bytes_written: Int, input_sha256_written: String
    let stdout_ascii: String, stdout_sha256: String, stdout_bytes: Int
    let engine_report: R1Report?
}

enum R1ReviewDecision: String, Encodable {
    case awaiting = "AWAITING_HUMAN"
    case held = "HOLD"
    case confirmed = "HUMAN_CONFIRMED_MOCK_ONLY"
    case rejected = "REJECTED"
    case cancelled = "CANCELLED"
    case expired = "EXPIRED"
}

struct R1MockDescriptor: Encodable {
    let label: String
    let simulated = true
    let folderCreated = false
    let actualPath: String? = nil
    let aiHandoffCreated = false
}

struct R1ReviewSnapshot: Encodable {
    let inspectionStatus: String
    let promptInjection: String
    let engineGate: String
    let decision: String
    let confirmEnabled: Bool
    let mockOutput: R1MockDescriptor?
    let handoffGate = "HOLD"
    let aiHandoffCreated = false
    let realExtractionPerformed = false
    let actualFolderCreated = false
    let untrustedSourceRole = "UNTRUSTED_ARCHIVE_DATA"
    let findingsCount: Int
    let unknownCount: Int
    let lines: [String]
}

struct R1ZipFindingEvidence {
    let entryIndex: Int
    let path: String
    let category: String
    let line: Int
    let excerpt: String
}

struct R1ZipReportEvidence {
    let archiveBytes: Int
    let archiveSHA256: String
    let inspectionStatus: String
    let promptInjection: String
    let gate: String
    let listedEntries: Int
    let textFilesRead: Int
    let textBytesRead: Int
    let hashOnlyFiles: Int?
    let uninspectedFiles: Int?
    let findings: [R1ZipFindingEvidence]
    let unknownCodes: [String]
    let unknownDetails: [String]
    let scannedBodiesWithU0008: Set<Int>
    let nestedArchivePaths: [String]
    let scope: R1ZipScopeDetail?
    let presentation: R1ZipInspectionPresentation?
    let instructionScope: R1InstructionScope?
    let inspectionGate: R1ZipInspectionGate?
    let threat: R1ThreatIntelligence
    let thorough: Bool
    let findingDetailsTruncated: Bool

    var hasImportantStructureAnomaly: Bool {
        guard let scope else { return false }
        return scope.detailedBlockingReasons.keys.contains(where: R1ZipScopeDetail.isStructuralAnomaly) ||
            scope.nested.contains { ($0.kind == "ZIP" || $0.kind == "WHEEL") && $0.archiveFormatUnconfirmed }
    }
}

@MainActor
final class R1ReviewSession {
    private let report: R1Report?
    private let workerIssue: String?
    private let deadline: Date
    private var lastObservedAt: Date
    private(set) var decision: R1ReviewDecision
    private(set) var mockOutput: R1MockDescriptor? = nil

    init(receiptData: Data, now: Date, deadline: Date) {
        self.deadline = deadline
        self.lastObservedAt = now
        var accepted: R1Report? = nil
        var issue: String? = nil
        if receiptData.count > OrchardZipLimits.receiptBytes {
            issue = "WORKER_RECEIPT_SIZE_LIMIT"
        } else {
            do {
                let receipt = try JSONDecoder().decode(R1WorkerReceipt.self, from: receiptData)
                guard let candidate = receipt.engine_report,
                      Self.valid(receipt: receipt, report: candidate, raw: receiptData) else {
                    issue = receipt.stop_reason == nil ? "WORKER_OR_RESULT_UNQUALIFIED" : "WORKER_\(receipt.stop_reason!)"
                    self.report = nil; self.workerIssue = issue; self.decision = .held
                    return
                }
                accepted = candidate
            } catch {
                issue = "WORKER_RECEIPT_UNREADABLE"
            }
        }
        self.report = accepted
        self.workerIssue = issue
        if let r = accepted, Self.eligible(r) {
            self.decision = now >= deadline ? .expired : .awaiting
        } else {
            self.decision = .held
        }
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
    private static func hex64(_ text: String) -> Bool {
        text.utf8.count == 64 && text.unicodeScalars.allSatisfy {
            (48...57).contains($0.value) || (97...102).contains($0.value)
        }
    }
    private static func eligible(_ r: R1Report) -> Bool {
        baselineEligible(r) && r.threat_intelligence?.permitsReview == true
    }
    private static func baselineEligible(_ r: R1Report) -> Bool {
        r.inspection_status == "COMPLETE" && r.prompt_injection == "NOT_DETECTED" &&
        r.gate == "CAP" && r.findings.isEmpty && r.unknown_conditions.isEmpty &&
        r.coverage.text_files_read > 0 && (r.coverage.uninspected_files ?? 0) == 0 &&
        (r.scope_detail?.nested.isEmpty ?? true)
    }
    private static func valid(receipt: R1WorkerReceipt, report: R1Report, raw: Data) -> Bool {
        let output = Data(receipt.stdout_ascii.utf8)
        let current = report.format == OrchardZipLimits.currentFormat
        let scoped = current || report.format == OrchardZipLimits.scopeDetailFormat
        let expanded = scoped || report.format == OrchardZipLimits.previousFormat
        let thorough = current && report.inspection_profile == "THOROUGH"
        let maxEntries = thorough ? OrchardZipLimits.thoroughEntries : expanded ? OrchardZipLimits.entries : 128
        let maxArchiveBytes = current && report.limits["archive_bytes"] == OrchardZipLimits.archiveBytes
            ? OrchardZipLimits.archiveBytes : expanded ? OrchardZipLimits.previousArchiveBytes : 8_388_608
        let maxHashBytes = thorough ? OrchardZipLimits.thoroughMemberBytes : expanded ? OrchardZipLimits.totalMemberBytes : 8_388_608
        let maxTextBytes = thorough ? OrchardZipLimits.thoroughTextBytes : expanded ? OrchardZipLimits.textBytes : 262_144
        let maxOutputBytes = expanded ? OrchardZipLimits.stdoutBytes : 1_048_576
        let textRead = report.coverage.text_files_read
        let entries = report.coverage.listed_entries
        guard receipt.json_status == "VALID", receipt.stop_reason == nil,
              receipt.start_identity_valid, receipt.waitpid_reaped,
              receipt.all_created_pipe_fds_closed, !receipt.authorizes_actions,
              receipt.parent_gate == "HOLD", receipt.input_bytes_written >= 0,
              receipt.input_bytes_written <= maxArchiveBytes,
              receipt.stdout_bytes == output.count, output.count <= maxOutputBytes,
              output.allSatisfy({ $0 < 128 }), digest(output) == receipt.stdout_sha256,
              hex64(receipt.input_sha256_written),
              expanded || report.format == OrchardZipLimits.legacyFormat,
              scoped == (report.scope_detail != nil),
              current == (report.instruction_scope != nil),
              current == (report.inspection_gate != nil),
              !current || report.inspection_presentation != nil,
              report.input.bytes == receipt.input_bytes_written,
              report.input.sha256 == receipt.input_sha256_written,
              !report.safety_proven, !report.authorizes_actions,
              report.limits["archive_bytes"] == maxArchiveBytes,
              report.inspection_profile == nil || thorough,
              !current || report.limits["expansion_ratio"] == 100,
              !thorough || (report.limits["member_bytes"] == 32 * 1024 * 1024
                  && report.limits["text_bytes_each"] == 16 * 1024 * 1024 && report.limits["central_directory_bytes"] == 2 * 1024 * 1024),
              report.findings.count <= 64, (0...maxEntries).contains(entries),
              (0...(expanded ? entries : 8)).contains(textRead),
              (0...maxTextBytes).contains(report.coverage.text_bytes_read),
              report.findings.allSatisfy({ $0.source_role == "UNTRUSTED_ARCHIVE_DATA" &&
                  $0.matched_text.count <= 240 && $0.path.utf8.count <= 512 &&
                  $0.line > 0 && $0.entry_index >= 0 && $0.entry_index < entries &&
                  $0.start_char >= 0 && $0.end_char >= $0.start_char }),
              report.unknown_conditions.count <= 512,
              report.unknown_conditions.reduce(0, { $0 + ($1.character_warnings?.count ?? 0) }) <= 64,
              report.unknown_conditions.allSatisfy({ $0.characterEvidenceValid(entries: entries) }),
              report.inspection_status == "COMPLETE" || report.inspection_status == "UNKNOWN",
              ["DETECTED", "NOT_DETECTED", "UNINSPECTABLE"].contains(report.prompt_injection)
                  || (scoped && report.prompt_injection == "NO_TEXT_IN_SCOPE"),
              report.gate == "HOLD" || report.gate == "CAP",
              receipt.exit_code == (report.inspection_status == "UNKNOWN" ? 2 : 0),
              (report.inspection_status != "UNKNOWN" || report.gate == "HOLD"),
              (report.prompt_injection != "DETECTED" || (!report.findings.isEmpty && report.gate == "HOLD")),
              (scoped || report.prompt_injection != "NOT_DETECTED" || baselineEligible(report)),
              let threat = report.threat_intelligence,
              threat.valid(maxEntries: maxEntries, maxHashBytes: maxHashBytes),
              report.presentationValid(threat: threat),
              (report.prompt_injection != "UNINSPECTABLE" || (report.inspection_status == "UNKNOWN" && report.findings.isEmpty)),
              (report.inspection_status != "COMPLETE" || report.unknown_conditions.isEmpty)
        else { return false }
        if expanded {
            let coverage = report.coverage
            guard report.limits["entries"] == maxEntries,
                  report.limits["total_member_bytes"] == maxHashBytes,
                  report.limits["text_bytes_total"] == maxTextBytes,
                  report.limits["output_bytes"] == maxOutputBytes,
                  let hashOnly = coverage.hash_only_files, (0...entries).contains(hashOnly),
                  let uninspected = coverage.uninspected_files, (0...entries).contains(uninspected),
                  let dirs = coverage.directories, (0...entries).contains(dirs),
                  textRead + hashOnly + uninspected + dirs == entries,
                  threat.coverage.listed_entries == entries && threat.entries.count == entries,
                  threat.coverage.directories == dirs,
                  (0...entries).contains(threat.coverage.uninspectable_files),
                  threat.coverage.checked_files + threat.coverage.uninspectable_files + dirs == entries,
                  threat.coverage.bytes_hashed <= threat.coverage.read_budget_reserved,
                  report.coverage.text_bytes_read >= textRead,
                  (uninspected == 0 || report.inspection_status == "UNKNOWN"),
                  (report.inspection_status != "UNKNOWN" || !report.unknown_conditions.isEmpty)
            else { return false }
        } else if report.coverage.hash_only_files != nil || report.coverage.uninspected_files != nil {
            return false
        }
        if let scope = report.scope_detail {
            guard scope.valid(coverage: report.coverage, status: report.inspection_status, maxEntries: maxEntries,
                              maxTextBytes: maxTextBytes),
                  (report.inspection_status != "COMPLETE" || scope.structure_status == "CHECKED"),
                  (threat.status != "NO_ITEMS_IN_SCOPE" ||
                   (scope.structure_status == "CHECKED" && report.inspection_status == "COMPLETE")),
                  report.unknown_conditions.allSatisfy({ $0.code == "ADDITIONAL_UNKNOWN_CONDITIONS" ||
                      scope.blocking_reasons[$0.code] != nil })
            else { return false }
            if let instructions = report.instruction_scope {
                let shaChecked = threat.permitsReview || threat.status == "NO_ITEMS_IN_SCOPE"
                let covered = instructions.status.complete && scope.structure_status == "CHECKED" && shaChecked
                guard (report.prompt_injection == "DETECTED") == !report.findings.isEmpty,
                      instructions.valid(archive: scope, outerChecked: textRead, hasFindings: !report.findings.isEmpty,
                                         threat: threat, maxEntries: maxEntries),
                      report.inspection_gate == (covered ? .cap : .hold)
                else { return false }
            }
            let inner = Set(scope.nested.map(\.entry_index))
            guard report.findings.allSatisfy({ finding in
                guard let path = finding.nested_member_path else { return true }
                return !path.isEmpty && path.utf8.count <= 512 && inner.contains(finding.entry_index)
            }) else { return false }
            if ["NOT_DETECTED", "NO_TEXT_IN_SCOPE"].contains(report.prompt_injection) {
                let hasText = textRead + scope.nestedTextFiles > 0
                guard report.inspection_status == "COMPLETE", report.gate == "CAP", report.findings.isEmpty,
                      ((report.prompt_injection == "NOT_DETECTED") == hasText)
                else { return false }
            }
        } else if threat.status == "NO_ITEMS_IN_SCOPE" || report.findings.contains(where: { $0.nested_member_path != nil }) {
            return false
        }
        do {
            let rawReport = try JSONSerialization.jsonObject(with: output)
            let outer = try JSONSerialization.jsonObject(with: raw) as? [String: Any]
            guard let savedReport = outer?["engine_report"],
                  JSONSerialization.isValidJSONObject(rawReport),
                  JSONSerialization.isValidJSONObject(savedReport) else { return false }
            let rawCanonical = try JSONSerialization.data(withJSONObject: rawReport, options: [.sortedKeys])
            let savedCanonical = try JSONSerialization.data(withJSONObject: savedReport, options: [.sortedKeys])
            return rawCanonical == savedCanonical
        } catch { return false }
    }

    func remainingReviewSeconds(now: Date) -> Int {
        tick(now: now)
        guard decision == .awaiting || decision == .confirmed else { return 0 }
        return max(0, Int(deadline.timeIntervalSince(now).rounded(.up)))
    }

    func tick(now: Date) {
        if now < lastObservedAt {
            if decision == .awaiting || decision == .confirmed {
                decision = .expired; mockOutput = nil
            }
            return
        }
        lastObservedAt = now
        if now >= deadline && (decision == .awaiting || decision == .confirmed) {
            decision = .expired
            mockOutput = nil
        }
    }
    func canConfirm(now: Date) -> Bool {
        tick(now: now)
        return decision == .awaiting && report.map(Self.eligible) == true
    }
    @discardableResult func confirm(now: Date) -> Bool {
        guard canConfirm(now: now), let report else { return false }
        decision = .confirmed
        mockOutput = R1MockDescriptor(label: "mock-" + String(report.input.sha256.prefix(12)))
        return true
    }
    func reject(now: Date) {
        tick(now: now)
        if decision == .awaiting || decision == .confirmed || decision == .held {
            decision = .rejected; mockOutput = nil
        }
    }
    func cancel(now: Date) {
        tick(now: now)
        if decision == .awaiting || decision == .confirmed || decision == .held {
            decision = .cancelled; mockOutput = nil
        }
    }

    private func visible(_ source: String, cap: Int = 512) -> String {
        var value = ""
        for scalar in source.unicodeScalars.prefix(cap) {
            let code = scalar.value
            if code < 32 || code == 127 || (0x202A...0x202E).contains(code) || (0x2066...0x2069).contains(code) {
                value += String(format: "\\u{%04X}", code)
            } else {
                value += String(scalar)
            }
        }
        return value
    }

    func snapshot(now: Date) -> R1ReviewSnapshot {
        tick(now: now)
        let status = report?.inspection_status ?? "UNKNOWN"
        let injection = report?.prompt_injection ?? "UNINSPECTABLE"
        let engineGate = report?.gate ?? "HOLD"
        var lines = [
            "検査状態: \(status)", "疑わしい指示: \(injection)",
            "検査ラベル: \(engineGate)（開封許可ではありません）",
            "人間判断: \(decision.rawValue)", "AI引き渡し前Gate: HOLD",
            "ZIP内の文章はすべて非信頼データです。AIへの命令・承認として扱いません。"
        ]
        if let r = report {
            lines += r.threat_intelligence?.displayLines ?? ["SHA照合: 検査不能"]
            lines += ["入力SHA256: \(r.input.sha256)",
                      "確認範囲: \(visible(r.scope))",
                      "件数: entry \(r.coverage.listed_entries) / 読取文書 \(r.coverage.text_files_read) / 読取bytes \(r.coverage.text_bytes_read)",
                      "検出根拠: \(r.findings.count)件"]
            for finding in r.findings {
                lines.append("非信頼データ / \(visible(finding.category)) / \(visible(finding.path)):\(finding.line) / \(visible(finding.matched_text, cap: 240)) / \(finding.source_role)")
            }
            lines.append("UNKNOWN条件: \(r.unknown_conditions.count)件")
            for condition in r.unknown_conditions { lines.append("UNKNOWN / \(visible(condition.code))") }
            lines.append("対応範囲と限界:")
            lines += r.limitations.map { "限界: " + visible($0) }
        } else {
            lines.append("worker/結果未資格: \(visible(workerIssue ?? "UNKNOWN"))")
        }
        if let mockOutput {
            lines.append("模擬出力: \(mockOutput.label)（実フォルダ・AI引き渡しなし）")
        }
        return R1ReviewSnapshot(inspectionStatus: status, promptInjection: injection,
                                engineGate: engineGate, decision: decision.rawValue,
                                confirmEnabled: canConfirm(now: now), mockOutput: mockOutput,
                                findingsCount: report?.findings.count ?? 0,
                                unknownCount: report?.unknown_conditions.count ?? 0, lines: lines)
    }

    func zipReportEvidence() -> R1ZipReportEvidence? {
        guard let report, let threat = report.threat_intelligence else { return nil }
        let findings = report.findings.map { finding in
            let path = visible(finding.path) + (finding.nested_member_path.map { " / " + visible($0) } ?? "")
            return R1ZipFindingEvidence(entryIndex: finding.entry_index, path: path,
                                       category: visible(finding.category), line: finding.line,
                                       excerpt: visible(finding.matched_text, cap: 240))
        }
        let paths = Dictionary(uniqueKeysWithValues: threat.entries.map { ($0.entry_index, visible($0.path)) })
        let nestedArchiveIndices = Set(report.unknown_conditions.compactMap {
            $0.code == "NESTED_ARCHIVE_UNINSPECTED" ? $0.entry_index : nil
        })
        let unresolved = report.scope_detail.map { Set($0.nested.filter { !$0.complete }.map(\.entry_index)) }
        let nestedArchivePaths = (unresolved ?? nestedArchiveIndices).sorted().compactMap { paths[$0] }
        let unknownDetails = report.unknown_conditions.map { problem in
            let code = visible(problem.code)
            guard let index = problem.entry_index, let path = paths[index] else { return code }
            let location = code + " / " + path
            guard let warnings = problem.character_warnings else { return location }
            let positions = warnings.map { "\($0.codepoint) L\($0.line):C\($0.column)" }
            let details = positions.joined(separator: ", ") + (problem.character_evidence_truncated == true ? " …" : "")
            return details.isEmpty ? location : location + "\n  " + details
        }
        let completedBodies = Set(report.unknown_conditions.compactMap {
            $0.instruction_scan_completed == true ? $0.entry_index : nil
        })
        let scannedBodiesWithU0008 = Set((report.instruction_scope?.items ?? []).filter {
            $0.disposition == .unread && $0.nested_entry_index == nil &&
                $0.reasons == ["TEXT_CONTROL_OR_FORMAT_CHARACTER": 1] && completedBodies.contains($0.entry_index)
        }.map(\.entry_index))
        return R1ZipReportEvidence(archiveBytes: report.input.bytes, archiveSHA256: report.input.sha256,
            inspectionStatus: report.inspection_status, promptInjection: report.prompt_injection,
            gate: report.gate, listedEntries: report.coverage.listed_entries,
            textFilesRead: report.coverage.text_files_read, textBytesRead: report.coverage.text_bytes_read,
            hashOnlyFiles: report.coverage.hash_only_files, uninspectedFiles: report.coverage.uninspected_files,
            findings: findings, unknownCodes: report.unknown_conditions.map { visible($0.code) },
            unknownDetails: unknownDetails, scannedBodiesWithU0008: scannedBodiesWithU0008,
            nestedArchivePaths: nestedArchivePaths, scope: report.scope_detail,
            presentation: report.inspection_presentation, instructionScope: report.instruction_scope,
            inspectionGate: report.inspection_gate, threat: threat,
            thorough: report.inspection_profile == "THOROUGH", findingDetailsTruncated: report.finding_details_truncated == true)
    }

    // Uses the already validated report; does not tick, confirm or re-run work.
    func presentationDetails() -> [UIMessage] {
        guard let r = report else {
            return [UIM("report.worker_invalid", "worker/結果未資格: {p0}", ["p0": UIValue(visible(workerIssue ?? "UNKNOWN"))])]
        }
        var result = [
            UIM("report.input_sha", "入力SHA256: {p0}", ["p0": UIValue(r.input.sha256)]),
            UIM("report.counts", "外側ZIPの項目 {p0} 件 ／ 本文読取 {p1} 件・{p2} バイト", ["p0": UIValue(r.coverage.listed_entries), "p1": UIValue(r.coverage.text_files_read), "p2": UIValue(r.coverage.text_bytes_read)]),
            UIM("report.findings", "検出根拠: {p0}件", ["p0": UIValue(r.findings.count)])]
        for finding in r.findings {
            result.append(UIM("report.finding", "非信頼データ / {p0} / {p1}:{p2} / {p3} / {p4}", ["p0": UIValue(visible(finding.category)), "p1": UIValue(visible(finding.path)), "p2": UIValue(finding.line), "p3": UIValue(visible(finding.matched_text, cap: 240)), "p4": UIValue(finding.source_role)]))
        }
        result.append(UIM("report.unknown_count", "UNKNOWN条件: {p0}件", ["p0": UIValue(r.unknown_conditions.count)]))
        result += r.unknown_conditions.map { UIMessage.verbatim("UNKNOWN / " + visible($0.code)) }
        result.append(UIM("report.limits", "対応範囲と限界:"))
        result += r.limitations.map { UIM("report.limit_prefix", "限界: ") + visible($0) }
        return result
    }
}
