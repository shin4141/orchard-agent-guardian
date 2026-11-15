import Foundation
import CryptoKit

// A3 consumes saved A2 evidence. ZIP text is data and never supplies an action.
private struct R1Input: Decodable { let bytes: Int; let sha256: String }
private struct R1Coverage: Decodable { let listed_entries: Int; let text_files_read: Int; let text_bytes_read: Int }
private struct R1Finding: Decodable {
    let category: String, path: String, matched_text: String, source_role: String
    let line: Int, entry_index: Int, start_char: Int, end_char: Int
}
private struct R1Unknown: Decodable { let code: String; let entry_index: Int? }
private struct R1Report: Decodable {
    let format: String, inspection_status: String, prompt_injection: String, gate: String
    let input: R1Input
    let findings: [R1Finding], unknown_conditions: [R1Unknown]
    let coverage: R1Coverage, limits: [String: Int]
    let scope: String, limitations: [String]
    let safety_proven: Bool, authorizes_actions: Bool
    let threat_intelligence: R1ThreatIntelligence?
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
        if receiptData.count > 1_048_576 {
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
        r.coverage.text_files_read > 0
    }
    private static func valid(receipt: R1WorkerReceipt, report: R1Report, raw: Data) -> Bool {
        let output = Data(receipt.stdout_ascii.utf8)
        guard receipt.json_status == "VALID", receipt.stop_reason == nil,
              receipt.start_identity_valid, receipt.waitpid_reaped,
              receipt.all_created_pipe_fds_closed, !receipt.authorizes_actions,
              receipt.parent_gate == "HOLD", receipt.input_bytes_written >= 0,
              receipt.input_bytes_written <= 8_388_608,
              receipt.stdout_bytes == output.count, output.count <= 1_048_576,
              output.allSatisfy({ $0 < 128 }), digest(output) == receipt.stdout_sha256,
              hex64(receipt.input_sha256_written),
              report.format == "orchard-c-static-zip/1.0",
              report.input.bytes == receipt.input_bytes_written,
              report.input.sha256 == receipt.input_sha256_written,
              !report.safety_proven, !report.authorizes_actions,
              report.limits["archive_bytes"] == 8_388_608,
              report.findings.count <= 64, report.coverage.listed_entries <= 128,
              report.coverage.text_files_read <= 8,
              report.coverage.text_bytes_read <= 262_144,
              report.findings.allSatisfy({ $0.source_role == "UNTRUSTED_ARCHIVE_DATA" &&
                  $0.matched_text.count <= 240 && $0.path.utf8.count <= 512 &&
                  $0.line > 0 && $0.entry_index >= 0 && $0.start_char >= 0 && $0.end_char >= $0.start_char }),
              report.unknown_conditions.count <= 512,
              report.inspection_status == "COMPLETE" || report.inspection_status == "UNKNOWN",
              report.prompt_injection == "DETECTED" || report.prompt_injection == "NOT_DETECTED" || report.prompt_injection == "UNINSPECTABLE",
              report.gate == "HOLD" || report.gate == "CAP",
              receipt.exit_code == (report.inspection_status == "UNKNOWN" ? 2 : 0),
              (report.inspection_status != "UNKNOWN" || report.gate == "HOLD"),
              (report.prompt_injection != "DETECTED" || (!report.findings.isEmpty && report.gate == "HOLD")),
              (report.prompt_injection != "NOT_DETECTED" || baselineEligible(report)),
              report.threat_intelligence?.valid == true,
              (report.prompt_injection != "UNINSPECTABLE" || (report.inspection_status == "UNKNOWN" && report.findings.isEmpty)),
              (report.inspection_status != "COMPLETE" || report.unknown_conditions.isEmpty)
        else { return false }
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
}

