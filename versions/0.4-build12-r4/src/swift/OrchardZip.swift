import AppKit
import QuartzCore
import CryptoKit
import Darwin
import Foundation
import UniformTypeIdentifiers

// Same implementation used by the pinned R1 direct-child port.
func hash54(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

enum OrchardFault: String, Error { case input, changed, identity, result }

struct OrchardZipSizeLimit: Error {
    let inputBytes: Int64

    var guidance: UIMessage {
        UIM("zip.failure.archiveTooLarge",
            "入力{p0}バイトはZIPの上限（{p1} MiB）を超えています。本文は未検査です。AIへの受け渡しを保留し、検査する場合は上限内のZIPを選んでください。",
            ["p0": UIValue(inputBytes), "p1": UIValue(OrchardZipLimits.archiveMiB)])
    }
}

struct OrchardWorkerIdentity {
    let app: URL
    let executable: URL
    let executableSHA256: String
    let inspectionSourceSHA256: String?
    let entryPath: String
    let snapshotPath: String

    static func load(in bundle: URL = Bundle.main.bundleURL) throws -> OrchardWorkerIdentity {
        _ = try SentinelRuntime.load(bundle)
        let manifest = bundle.appendingPathComponent("Contents/Resources/WorkerManifest.json")
        let raw = try Data(contentsOf: manifest, options: .mappedIfSafe)
        guard raw.count < 524_288,
              let object = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
              object["schema"] as? String == "orchard-private-300k-worker/1",
              object["sandbox"] as? String == "APP_SANDBOX_STANDALONE_NO_FILE_OR_NETWORK_ENTITLEMENTS",
              object["db_sha256"] as? String == "d778e4ec37eb300f87cee82a891cd85738f1ae095dfdadf27006db78c7537b95",
              let entries = object["files"] as? [[String: Any]], !entries.isEmpty, entries.count < 512 else {
            throw OrchardFault.identity
        }
        let app = bundle.appendingPathComponent("Contents/Helpers/OrchardInspection.app").standardizedFileURL
        guard app.resolvingSymlinksInPath() == app.standardizedFileURL,
              Bundle(url: app)?.bundleIdentifier == SentinelResidencyBuild.mainID + ".worker" else { throw OrchardFault.identity }
        var expected = Set<String>()
        var executableHash: String?
        var inspectionSourceHash: String?
        for entry in entries {
            guard let relative = entry["path"] as? String, !relative.hasPrefix("/"),
                  relative.utf8.count < 1024,
                  !relative.split(separator: "/", omittingEmptySubsequences: false).contains(where: {
                      $0.isEmpty || $0 == "." || $0 == ".."
                  }), expected.insert(relative).inserted else { throw OrchardFault.identity }
            let path = app.appendingPathComponent(relative)
            guard path.resolvingSymlinksInPath().path.hasPrefix(app.path + "/") else { throw OrchardFault.identity }
            var info = stat()
            guard lstat(path.path, &info) == 0 else { throw OrchardFault.identity }
            if let link = entry["symlink"] as? String {
                guard info.st_mode & S_IFMT == S_IFLNK, !link.hasPrefix("/"),
                      try FileManager.default.destinationOfSymbolicLink(atPath: path.path) == link else {
                    throw OrchardFault.identity
                }
            } else {
                guard info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
                      let bytes = entry["size"] as? Int, bytes == info.st_size, bytes <= 134_217_728,
                      let sha = entry["sha256"] as? String,
                      hash54(try Data(contentsOf: path)) == sha else { throw OrchardFault.identity }
                if relative == "Contents/MacOS/OrchardZipWorker" { executableHash = sha }
                if relative == "Contents/Resources/r1_snapshot.py" { inspectionSourceHash = sha }
            }
        }
        let actual = try SentinelRuntime.inventoryPaths(in: app)
        let required: Set<String> = ["Contents/MacOS/OrchardZipWorker", "Contents/Resources/warehouse_worker_entry.py",
            "Contents/Resources/feed_adapter.py", "Contents/Resources/warehouse_code/warehouse.py", "Contents/Resources/bounded_reader.py", "Contents/Resources/POLICY.json", "Contents/Resources/r1_snapshot.py", "Contents/Resources/inspection.py",
            "Contents/Resources/threat_db.py", "Contents/Resources/warehouse/current.json", "Contents/Resources/warehouse/g-a5e38cbf56364a3ba6deac193ff7652c/manifest.json", "Contents/Resources/warehouse/g-a5e38cbf56364a3ba6deac193ff7652c/hashes.sqlite3", "Contents/Resources/warehouse/g-a5e38cbf56364a3ba6deac193ff7652c/suppression.json"]
        guard actual == expected, required.isSubset(of: expected), let sha = executableHash else { throw OrchardFault.identity }
        return OrchardWorkerIdentity(app: app, executable: URL(fileURLWithPath: try SentinelRuntime.physicalPath(app.appendingPathComponent("Contents/MacOS/OrchardZipWorker"), inside: app)), executableSHA256: sha,
            inspectionSourceSHA256: inspectionSourceHash,
            entryPath: try SentinelRuntime.physicalPath(app.appendingPathComponent("Contents/Resources/warehouse_worker_entry.py"), inside: app),
            snapshotPath: try SentinelRuntime.physicalPath(app.appendingPathComponent("Contents/Resources/warehouse/current.json"), inside: app))
    }

    func runtime(mode: OrchardWarehouseMode, thorough: Bool = false, progressTargets: [String] = []) -> R1WorkerRuntime {
        let bundle = Bundle.main.bundleURL
        let option = progressTargets.isEmpty ? "--thorough" : "--thorough=" + progressTargets.joined(separator: ",")
        return R1WorkerRuntime(executable: executable,
            argvTail: ["-I", "-S", "-B", entryPath,
                       "--fd=0", "--manifest=" + snapshotPath, "--verification-mode=" + mode.rawValue] +
                       (thorough ? [option] : []),
            environment: SentinelRuntime.environment, engine: nil, expectedExecutableSHA256: executableSHA256,
            label: "ORCHARD_PRIVATE_REAL_BOUNDED_300000_SANDBOXED",
            validateFreshAtUse: { _ = try OrchardWorkerIdentity.load(in: bundle) })
    }
}

// A new, one-shot job owns cancellation and the direct-child port. No old
// Session/Authority, extraction receiver, AI handoff or watched code is loaded.
enum OrchardWarehouseMode: String {
    case live = "LIVE"
    case expired = "AFTER_25H_SIMULATION"
    case failed = "UPDATE_FAILED_SIMULATION"
}

final class OrchardZipJob: @unchecked Sendable {
    let cancellation = R1WorkerCancellation()
    let url: URL
    private(set) var resourcesQuiescent = true
    private(set) var reportInspectionSourceSHA256: String?
    let mode: OrchardWarehouseMode
    let expectedSHA256: String?
    let progressTargets: [String]
    var thorough: Bool { expectedSHA256 != nil }
    init(url: URL, mode: OrchardWarehouseMode = .live, expectedSHA256: String? = nil, progressTargets: [String] = []) {
        self.url = url
        self.mode = mode
        self.expectedSHA256 = expectedSHA256
        self.progressTargets = progressTargets
    }

    func run(onProgress: ((Int) -> Void)? = nil) throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw OrchardFault.input }
        defer { close(fd) }
        var before = stat(), after = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_nlink == 1,
              before.st_size > 0 else { throw OrchardFault.input }
        guard before.st_size <= Int64(OrchardZipLimits.archiveBytes) else {
            throw OrchardZipSizeLimit(inputBytes: before.st_size)
        }
        // The same owned, anonymous copy feeds the worker and the input digest.
        var temporary = Array((NSTemporaryDirectory() + "orchard-input-XXXXXX").utf8CString)
        let owned = mkstemp(&temporary)
        guard owned >= 0 else { throw OrchardFault.input }
        defer { close(owned) }
        guard unlink(temporary) == 0, fchmod(owned, 0o600) == 0 else { throw OrchardFault.input }
        let input = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        let copy = FileHandle(fileDescriptor: owned, closeOnDealloc: false)
        var copiedBytes: Int64 = 0
        var hasher = SHA256()
        while let chunk = try input.read(upToCount: 65_536), !chunk.isEmpty {
            guard !cancellation.requested else { throw R1WorkerPortFault.cancelled }
            copiedBytes += Int64(chunk.count)
            guard copiedBytes <= before.st_size else { throw OrchardFault.changed }
            hasher.update(data: chunk)
            try copy.write(contentsOf: chunk)
        }
        guard copiedBytes == before.st_size, fstat(fd, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw OrchardFault.changed }
        let digest = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        if let expectedSHA256, expectedSHA256 != digest { throw OrchardFault.changed }
        guard lseek(owned, 0, SEEK_SET) == 0 else { throw OrchardFault.input }
        let identity = try OrchardWorkerIdentity.load()
        let port = R1WorkerProcessPort(runtime: identity.runtime(mode: mode, thorough: thorough,
                                                               progressTargets: progressTargets))
        resourcesQuiescent = false
        defer { resourcesQuiescent = port.resourcesQuiescent }
        let receipt = try port.runOnce(inputFD: owned, inputBytes: copiedBytes, inputSHA256: digest,
            deadline: thorough ? OrchardZipLimits.thoroughHostSeconds : 10.0, cancellation: cancellation,
            progressTargetCount: progressTargets.count, onProgress: onProgress)
        guard port.resourcesQuiescent else { throw OrchardFault.result }
        if mode == .live { reportInspectionSourceSHA256 = identity.inspectionSourceSHA256 }
        return receipt
    }
}

private func orchardVisible(_ text: String) -> String {
    text.unicodeScalars.prefix(512).map { scalar in
        let code = scalar.value
        return code < 32 || (0x7f...0x9f).contains(code) || (0x202a...0x202e).contains(code) ||
            (0x2066...0x2069).contains(code) ? String(format: "\\u{%04X}", code) : String(scalar)
    }.joined()
}

// The diagnostic CLI and the visible UI validate and present the same receipt.
@MainActor func orchardZipSnapshot(receipt: Data, name: String,
                                   reportInspectionSourceSHA256: String? = nil) throws -> OrchardZipDisplaySnapshot {
    let now = Date()
    let review = R1ReviewSession(receiptData: receipt, now: now, deadline: now.addingTimeInterval(300))
    guard let evidence = review.zipReportEvidence() else { throw OrchardFault.result }
    let offer = OrchardReportB8.payload(for: evidence, inspectionSourceSHA256: reportInspectionSourceSHA256).map {
        OrchardReportOfferB8(payload: $0, inspectionReceiptSHA256: hash54(receipt), admittedAt: now)
    }
    return OrchardZipDisplaySnapshot(name: name, evidence: evidence, details: review.presentationDetails(), reportOffer: offer)
}

struct OrchardZipDisplaySnapshot {
    let name: String
    let evidence: R1ZipReportEvidence
    let details: [UIMessage]
    let reportOffer: OrchardReportOfferB8?
    var ti: R1ThreatIntelligence { evidence.threat }
    var promptInjection: String { evidence.promptInjection }
    var frameTone: OrchardPearlFrameTone { OrchardPearlFrameTone(accepted: evidence) }

    func outerTextCoverage(_ scope: R1ZipScopeDetail) -> UIMessage {
        let counts = [
            "p0": UIValue(evidence.textFilesRead), "p1": UIValue(scope.ordinary_out_of_scope),
            "p2": UIValue(scope.outer_unresolved)
        ]
        if evidence.presentation != nil {
            return UIM("zip.scope.outerCoverage", "外側の本文　読取 {p0} 件 ／ SHAのみ {p1} 件 ／ 本文未確認 {p2} 件", counts)
        }
        return UIM("zip.scope.outerText", "外側の本文　読取 {p0} 件 ／ 対象外 {p1} 件 ／ 未確認 {p2} 件", counts)
    }

    var scopeLines: [UIMessage] {
        guard let scope = evidence.scope else { return [] }
        let structure = scope.structure_status == "CHECKED"
            ? UIM("zip.scope.structureChecked", "外側ZIPの構造情報　確認済み")
            : UIM("zip.scope.structurePartial", "外側ZIPの構造　制約あり")
        let nested = UIM("zip.scope.innerText", "内側アーカイブ　{p0} 件中 {p1} 件に未確認あり ／ 本文読取 {p2} 件", [
            "p0": UIValue(scope.nested.count), "p1": UIValue(scope.nestedRemaining), "p2": UIValue(scope.nestedTextFiles)
        ])
        return [structure, outerTextCoverage(scope), nested]
    }

    var zeroDocumentReason: UIMessage? {
        guard evidence.inspectionStatus == "UNKNOWN", promptInjection == "UNINSPECTABLE",
              evidence.textFilesRead == 0 else { return nil }
        let reasons = evidence.unknownCodes
        if reasons.contains("NO_SUPPORTED_TEXT") || reasons.contains("NO_ALLOWLISTED_TEXT") {
            return UIM("zip.instruction.zero.unsupported", "ZIP内に指示検査で読み取れるテキストが見つかりませんでした。")
        }
        if reasons.contains("TEXT_UNREADABLE_UnicodeDecodeError") {
            return UIM("zip.instruction.zero.encoding", "対象文書の文字コードを確認できませんでした。")
        }
        if reasons.contains("TEXT_BYTE_LIMIT") {
            return UIM("zip.instruction.zero.size", "対象文書が指示検査の読取上限を超えています。")
        }
        return UIM("zip.instruction.zero.unreadable", "指示検査で読み取れた文書は0件です。読み取れなかった理由は検査の詳細で確認できます。")
    }

    // This renders retained immutable values; no receipt validation/job is re-run.
    func render() -> [String: String] {
        if evidence.presentation != nil {
            let copy = OrchardZipResultCopy(snapshot: self)
            let language = UILanguagePreference.shared.language
            let prefix = ti.database.verification_mode == "LIVE" ? "" : UIL("zip.report.simulation", "【検証】")
            let actions = copy.actionGuidance.map { card in
                ([card.title] + card.body).map { $0.render(language) }.joined(separator: "\n")
            }
            let visibleEvidence = copy.firstActionEvidence.map { $0.render(language) }.joined(separator: "\n")
            let summary = ([copy.file.render(language), visibleEvidence] + actions).filter { !$0.isEmpty }
                .joined(separator: "\n\n")
            var result = ["headline": prefix + copy.headline.render(language),
                    "body": summary + "\n\n" + copy.details(language: language),
                    "promptInjection": promptInjection]
            if let scan = evidence.instructionScope {
                result["instructionScope"] = scan.status.rawValue
                result["instructionTone"] = scan.status.tone.rawValue
                result["inspectionGate"] = evidence.inspectionGate?.rawValue
                result["frameTone"] = frameTone.rawValue
            }
            return result
        }
        let headline: String
        switch ti.status {
        case "KNOWN_HASH_MATCH": headline = UIL("zip.sha.match", "対象DBの既知SHAに一致しました")
        case "NO_MATCH_IN_COVERED_DB": headline = UIL("zip.sha.no_match", "対象DB内に一致はありません（安全の保証ではありません）")
        case "NO_ITEMS_IN_SCOPE": headline = UIL("zip.scope.shaNotApplicable", "外側ZIPにSHA照合の対象ファイルはありません")
        case "DB_NOT_UPDATED": headline = UIL("zip.sha.db_update", "DBの更新が必要です。不一致を判定できません")
        default: headline = UIL("zip.sha.incomplete", "検査を完了できない項目があります")
        }
        let instruction: UIMessage
        switch promptInjection {
        case "DETECTED": instruction = UIM("zip.instruction.detected", "疑わしい指示を検出しました")
        case "NOT_DETECTED": instruction = UIM("zip.instruction.not_detected", "対象規則内で疑わしい指示は検出されませんでした")
        case "NO_TEXT_IN_SCOPE": instruction = UIM("zip.scope.noText", "指示検査の対象となるテキストはありません")
        default: instruction = zeroDocumentReason ?? UIM("zip.instruction.incomplete", "指示の検査を完了できませんでした")
        }
        let lines = [UIL("ui.common.file", "ファイル: {p0}", ["p0": UIValue(orchardVisible(name))]), instruction.text, ""] +
            scopeLines.map { $0.text } +
            ti.presentationLines.map { $0.text } + ["", UIL("zip.report.details", "検査結果の詳細:")] + details.map { $0.text }
        return ["headline": (ti.database.verification_mode == "LIVE" ? "" : UIL("zip.report.simulation", "【検証】")) + headline,
                "body": lines.joined(separator: "\n"), "promptInjection": promptInjection]
    }
}
@MainActor func orchardZipPresentation(receipt: Data, name: String) throws -> [String: String] {
    try orchardZipSnapshot(receipt: receipt, name: name).render()
}

#if !ORCHARD_SAVED_REPORT_REHEARSAL
// The standalone product uses the payload schema from ReportActionBC.swift.
// Saved B8 preview and consent types are confined to the rehearsal target.
struct ReportPayloadBC: Codable, Equatable {
    let sha256: String
    let classification: String
    let finding_categories: [String]
    let inspection_version: String
    let destination: String
}
#endif

struct OrchardLocalReportApproval {
    let payload: ReportPayloadBC
    let detectionID: UUID
    let inspectionReceiptSHA256: String
    let inspectedAt: Int64
    let approvedAt: Int64

    fileprivate init(payload: ReportPayloadBC, detectionID: UUID, inspectionReceiptSHA256: String,
                     inspectedAt: Int64, approvedAt: Int64) {
        self.payload = payload
        self.detectionID = detectionID
        self.inspectionReceiptSHA256 = inspectionReceiptSHA256
        self.inspectedAt = inspectedAt
        self.approvedAt = approvedAt
    }

    fileprivate func matches(_ receipt: OrchardLocalReportReceipt) -> Bool {
        receipt.detectionID == detectionID && receipt.payload == payload &&
            receipt.inspectionReceiptSHA256 == inspectionReceiptSHA256 &&
            receipt.inspectedAt == inspectedAt && receipt.approvedAt == approvedAt
    }
}

enum OrchardLocalReportOutcome {
    case cancelled, stale, unresolved
    case accepted(OrchardLocalReportReceipt)
    case readBack(OrchardLocalReportReceipt)
}

// The immutable offer comes from the accepted inspection receipt. This latch
// lives on the result, so re-opening its sheet never starts another write.
@MainActor final class OrchardReportOfferB8 {
    let payload: ReportPayloadBC
    let detectionID = UUID()
    let inspectionReceiptSHA256: String
    let admittedAt: Date
    let admittedUptime: TimeInterval
    private var approval: OrchardLocalReportApproval?
    var attempted: Bool { approval != nil }

    fileprivate init(payload: ReportPayloadBC, inspectionReceiptSHA256: String, admittedAt: Date) {
        self.payload = payload
        self.inspectionReceiptSHA256 = inspectionReceiptSHA256
        self.admittedAt = admittedAt
        self.admittedUptime = ProcessInfo.processInfo.systemUptime
    }

    func isFresh(now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) -> Bool {
        (0..<300).contains(now.timeIntervalSince(admittedAt)) && (0..<300).contains(uptime - admittedUptime)
    }

    func confirm(explicit: Bool, current: Bool, now: Date = Date(),
                 uptime: TimeInterval = ProcessInfo.processInfo.systemUptime,
                 receive: (OrchardLocalReportApproval) throws -> OrchardLocalReportReceipt,
                 readBack: (OrchardLocalReportApproval) throws -> OrchardLocalReportReceipt?) -> OrchardLocalReportOutcome {
        guard explicit else { return .cancelled }
        guard current else { return .stale }
        if attempted { return reconcile(readBack) }
        guard isFresh(now: now, uptime: uptime) else { return .stale }
        let consent = OrchardLocalReportApproval(payload: payload, detectionID: detectionID,
            inspectionReceiptSHA256: inspectionReceiptSHA256, inspectedAt: Int64(admittedAt.timeIntervalSince1970),
            approvedAt: Int64(now.timeIntervalSince1970))
        approval = consent
        do {
            let result = try receive(consent)
            if consent.matches(result) { return .accepted(result) }
        } catch {
            // A write may already have committed. The following lookup is read-only.
        }
        return reconcile(readBack)
    }

    func reconcile(_ readBack: (OrchardLocalReportApproval) throws -> OrchardLocalReportReceipt?) -> OrchardLocalReportOutcome {
        guard let approval, let result = try? readBack(approval), approval.matches(result) else { return .unresolved }
        return .readBack(result)
    }
}

@MainActor enum OrchardReportB8 {
    private static let categories: Set<String> = [
        "INSTRUCTION_OVERRIDE", "ROLE_SPOOFING", "AUTHORITY_SPOOFING", "PRIVILEGE_REQUEST",
        "DATA_TRANSMISSION_REQUEST", "TOOL_EXECUTION_REQUEST", "FINDING_SUPPRESSION",
    ]

    private static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    static func payload(for evidence: R1ZipReportEvidence, inspectionSourceSHA256: String?) -> ReportPayloadBC? {
        guard let inspectionSourceSHA256, isSHA256(inspectionSourceSHA256), isSHA256(evidence.archiveSHA256),
              evidence.threat.database.verification_mode == "LIVE",
              evidence.promptInjection == "DETECTED", evidence.gate == "HOLD" else { return nil }
        let found = Set(evidence.findings.map(\.category))
        guard !found.isEmpty, found.isSubset(of: categories) else { return nil }
        return ReportPayloadBC(sha256: evidence.archiveSHA256, classification: "STATIC_SUSPICION",
            finding_categories: found.sorted(), inspection_version: "c-static-" + inspectionSourceSHA256,
            destination: "local:orchard-unverified-review")
    }

#if ORCHARD_SAVED_REPORT_REHEARSAL
    private static func reviewAlert(_ payload: ReportPayloadBC, language: UILanguage, scope: UIMessage) -> NSAlert {
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIM("zip.report.preview", "通報内容の確認").render(language)
        let ruleNames = payload.finding_categories.map { OrchardZipResultCopy.findingCategory($0).render(language) }
        alert.informativeText = [
            scope,
            UIM("zip.report.payloadSHA", "ZIP SHA-256  {p0}", ["p0": UIValue(payload.sha256)]),
            UIM("zip.report.payloadClass", "分類  疑わしい指示"),
            UIM("zip.report.payloadRules", "検出分類  {p0}", ["p0": UIValue(ruleNames.joined(separator: ", "))]),
            UIM("zip.report.payloadVersion", "検査版  {p0}", ["p0": UIValue(payload.inspection_version)]),
            UIM("zip.report.payloadPrivacy", "ZIP本体、ファイルパス、文書の原文、利用者IDは通報内容に含みません。"),
        ].map { $0.render(language) }.joined(separator: "\n\n")
        return alert
    }

    // The rehearsal uses the original ReportPortB8 and its saved-source
    // qualification at both steps. This is separate from the real ledger.
    static func reviewSavedFixture(_ offer: ReportOfferB8, port: ReportPortB8, language: UILanguage,
        current: () throws -> (ReportFrameB8, SavedReportSourceB8)) throws -> LocalReportReceiptB8? {
        do {
            let before = try current()
            let review = try port.beginReview(offer, frame: before.0, source: before.1,
                                              now: Int(Date().timeIntervalSince1970))
            let alert = reviewAlert(offer.preview.body.payload, language: language,
                scope: UIM("zip.report.savedFixture", "保存済みの合成所見です。承認すると端末内の試験受付に記録されます。"))
            let cancel = alert.addButton(withTitle: UIM("ui.common.cancel", "キャンセル").render(language))
            cancel.keyEquivalent = "\r"
            let approve = alert.addButton(withTitle: UIM("zip.report.approveLocal", "この内容を端末内で通報").render(language))
            approve.keyEquivalent = ""
            let explicit = alert.runModal() == .alertSecondButtonReturn
            let after = explicit ? try current() : before
            return try port.confirm(review, explicit: explicit, frame: after.0, source: after.1,
                                    now: Int(Date().timeIntervalSince1970))
        } catch {
            port.invalidatePresentation()
            throw error
        }
    }
#endif
}

@MainActor final class OrchardGitHubReportPreview: NSObject {
    private static let formURL = URL(string:
        "https://github.com/shin4141/orchard-zip-inspector/issues/new?template=orchard-inspection-report.yml")
    private let offer: OrchardReportOfferB8
    private let language: UILanguage
    private let current: () -> Bool
    private let writeSummary: (String) -> Bool
    private let status = NSTextField(labelWithString: "")
    let summary: String

    init(offer: OrchardReportOfferB8, language: UILanguage, current: @escaping () -> Bool,
         writeSummary: @escaping (String) -> Bool = { summary in
             let pasteboard = NSPasteboard.general
             pasteboard.clearContents()
             return pasteboard.setString(summary, forType: .string)
         }) {
        self.offer = offer
        self.language = language
        self.current = current
        self.writeSummary = writeSummary
        // The B8 offer admits only its fixed taxonomy. Use localized category labels
        // and fixed copy. Neither ZIP metadata nor inspection digests enter this summary.
        let categories = offer.payload.finding_categories.map {
            OrchardZipResultCopy.findingCategory($0).render(language)
        }
        summary = [
            UIM("zip.report.github.summary", "Orchardの検査で疑わしい指示を検出しました（未検証）。"),
            UIM("zip.report.payloadRules", "検出分類  {p0}", ["p0": UIValue(categories.joined(separator: ", "))]),
        ].map { $0.render(language) }.joined(separator: "\n")
        super.init()
    }

    private var allowed: Bool { current() && offer.isFresh() }
    private var stale: UIMessage {
        UIM("zip.report.github.stale", "この結果は期限切れか切り替わりました。ZIPをもう一度検査してください。")
    }

    func makeAlert() -> NSAlert {
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIM("zip.report.github.title", "公開前に検査要約を確認").render(language)
        alert.informativeText = UIM("zip.report.github.instructions",
            "Issueは公開されます。要約をコピーし、GitHubにログインしてフォームに貼り付け、ご自身で投稿してください。要約にZIP本体、原文、パス、SHA-256は含まれません。").render(language)
        let details = NSTextField(wrappingLabelWithString: summary)
        details.isSelectable = false
        details.maximumNumberOfLines = 0
        details.preferredMaxLayoutWidth = 380
        let copyButton = NSButton(title: UIM("zip.report.github.copy", "要約をコピー").render(language),
                                  target: self, action: #selector(copySummary))
        copyButton.setAccessibilityIdentifier("orchard.zip.report.github.copy")
        status.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        let panel = NSStackView(views: [details, copyButton, status])
        panel.orientation = .vertical
        panel.alignment = .leading
        panel.spacing = 8
        details.widthAnchor.constraint(equalToConstant: details.preferredMaxLayoutWidth).isActive = true
        panel.frame.size = panel.fittingSize
        alert.accessoryView = panel
        alert.addButton(withTitle: UIM("ui.common.close", "閉じる").render(language)).keyEquivalent = "\r"
        alert.addButton(withTitle: UIM("zip.report.github.open", "GitHubのフォームを開く").render(language)).keyEquivalent = ""
        return alert
    }

    @objc private func copySummary() {
        let message: UIMessage
        if !allowed {
            message = stale
        } else if writeSummary(summary) {
            message = UIM("zip.report.github.copied", "要約をコピーしました。")
        } else {
            message = UIM("zip.report.github.copyFailed", "要約をコピーできませんでした。")
        }
        status.stringValue = message.render(language)
    }

    func outcome(for response: NSApplication.ModalResponse,
                 open: (URL) -> Bool = { NSWorkspace.shared.open($0) }) -> UIMessage? {
        guard response == .alertSecondButtonReturn else { return nil }
        guard allowed else { return stale }
        guard let url = Self.formURL, open(url) else {
            return UIM("zip.report.github.openFailed", "GitHubのフォームを開けませんでした。")
        }
        return UIM("zip.report.github.browser", "ブラウザで内容を確認し、GitHubで投稿してください。")
    }

    func run() -> UIMessage? {
        guard allowed else { return stale }
        return outcome(for: makeAlert().runModal())
    }
}

// Presentation shared by the product window and the isolated AppKit preview.
@MainActor func orchardHomeCardHeading(_ title: NSTextField, symbol: String, hue: UInt32) -> NSStackView {
    let icon = OrchardZipResultCanvas()
    icon.setAccessibilityElement(false)
    icon.widthAnchor.constraint(equalToConstant: 25).isActive = true
    icon.heightAnchor.constraint(equalToConstant: 25).isActive = true
    icon.paint = { [weak icon] _ in
        guard let icon else { return }
        OrchardPearlArt.badge(symbol, color: hue, in: icon.bounds, system: OrchardPearlArt.prefersAccessibleMaterials)
    }
    let heading = NSStackView(views: [icon, title])
    heading.alignment = .centerY
    heading.spacing = 9
    return heading
}

@MainActor final class OrchardZipHomeControls {
    var onFrameChange: ((OrchardPearlFrameTone) -> Void)?
    let hero = NSStackView()
    let scope = NSStackView()
    let choose = OrchardPearlButton(title: "", target: nil, action: nil)
    let cancel = NSButton(title: "", target: nil, action: nil)
    let repeatCurrent = NSButton(title: "", target: nil, action: nil)
    let showResult = NSButton(title: "", target: nil, action: nil)
    private let title = NSTextField(wrappingLabelWithString: "")
    private let description = NSTextField(wrappingLabelWithString: "")
    private let scopeTitle = NSTextField(wrappingLabelWithString: "")
    private let status = NSTextField(wrappingLabelWithString: "")
    private let extraStatus = NSTextField(wrappingLabelWithString: "")
    private let instructionResult = NSTextField(wrappingLabelWithString: "")
    private let instructionIcon = NSImageView()
    private let output = NSTextField(wrappingLabelWithString: "")
    private let instructionSummary = NSStackView()
    private let secondaryActions = NSStackView()

    static let idleStatus = UIM("zip.not_selected", "ZIPはまだ選ばれていません")
    static let idleInstruction = UIM("zip.instruction.not_started", "指示の検査はまだ行っていません")
    static let baseline = UIM("zip.baseline.full", "実SHA300,000 unique件の限定倉庫（旧100,000件を保持・新規200,000件追加）を参照します。\n\n最新30万件や全期間の完全収録ではありません。一致なしは安全・開封・実行許可を意味しません。\n\n生成時刻・取得時刻を表示し、保存済み倉庫内の一致・未一致を照合します。25時間超のみでは保留しません。DBの整合性異常・検査不能・許諾撤回などは保留します。\n\n更新時は互換性を確認して既存の登録・未確認変更を引き継ぎます。旧版が監視中の場合は保留します。監視登録は1フォルダです。登録後に手動で監視を開始します。自動更新・ログイン登録は無効です。")

    init() {
        configureColumn(hero, spacing: 9)
        configureColumn(scope, spacing: 12)
        configureColumn(secondaryActions, spacing: 5)
        hero.setAccessibilityIdentifier("orchard.home.zip")
        scope.setAccessibilityIdentifier("orchard.home.scope.content")
        title.setAccessibilityIdentifier("orchard.home.zip.title")
        title.font = .systemFont(ofSize: 32, weight: .bold)
        description.font = .systemFont(ofSize: 14)
        description.textColor = .labelColor
        scopeTitle.font = .systemFont(ofSize: 18, weight: .semibold)
        status.font = .systemFont(ofSize: 13, weight: .medium)
        status.textColor = .secondaryLabelColor
        output.font = .systemFont(ofSize: 13)
        output.textColor = .secondaryLabelColor
        output.isSelectable = true
        output.lineBreakMode = .byWordWrapping
        extraStatus.font = .systemFont(ofSize: 14, weight: .semibold)
        extraStatus.setAccessibilityIdentifier("orchard.zip.thorough.status")
        for field in [title, description, status, extraStatus, scopeTitle, instructionResult, output] {
            field.maximumNumberOfLines = 0
            field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            field.setContentCompressionResistancePriority(.required, for: .vertical)
        }
        status.setAccessibilityIdentifier("orchard.zip.status")
        output.setAccessibilityIdentifier("orchard.zip.result")
        instructionResult.setAccessibilityIdentifier("orchard.zip.instructionResult")
        choose.appearanceRole = .primary
        choose.bezelStyle = .rounded
        choose.font = .systemFont(ofSize: 15, weight: .semibold)
        choose.image = NSImage(systemSymbolName: "doc.text.magnifyingglass", accessibilityDescription: nil)
        choose.imagePosition = .imageLeft
        choose.setAccessibilityIdentifier("orchard.zip.select")
        choose.heightAnchor.constraint(equalToConstant: 46).isActive = true
        choose.widthAnchor.constraint(greaterThanOrEqualToConstant: 188).isActive = true
        cancel.setAccessibilityIdentifier("orchard.zip.cancel")
        repeatCurrent.setAccessibilityIdentifier("orchard.zip.normal")
        showResult.setAccessibilityIdentifier("orchard.zip.showResult")
        for button in [cancel, repeatCurrent, showResult] {
            button.bezelStyle = .rounded
            secondaryActions.addArrangedSubview(button)
        }
        cancel.isEnabled = false
        repeatCurrent.isEnabled = false

        instructionIcon.image = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: nil)
        instructionIcon.imageScaling = .scaleProportionallyUpOrDown
        instructionIcon.contentTintColor = .systemRed
        instructionIcon.setAccessibilityIdentifier("orchard.zip.warningIcon")
        instructionIcon.setAccessibilityElement(false)
        instructionSummary.alignment = .centerY
        instructionSummary.spacing = 8
        instructionSummary.addArrangedSubview(instructionIcon)
        instructionSummary.addArrangedSubview(instructionResult)
        NSLayoutConstraint.activate([
            instructionIcon.widthAnchor.constraint(equalToConstant: 20),
            instructionIcon.heightAnchor.constraint(equalToConstant: 20)
        ])
        for item in [title, description, choose, extraStatus, secondaryActions, instructionSummary, status] {
            hero.addArrangedSubview(item)
        }
        hero.setCustomSpacing(13, after: description)
        let scopeHeading = orchardHomeCardHeading(scopeTitle, symbol: "list.bullet.rectangle", hue: 0x63788F)
        scope.addArrangedSubview(scopeHeading)
        scope.addArrangedSubview(output)
        NSLayoutConstraint.activate([
            title.widthAnchor.constraint(equalTo: hero.widthAnchor),
            description.widthAnchor.constraint(equalTo: hero.widthAnchor),
            instructionSummary.widthAnchor.constraint(equalTo: hero.widthAnchor),
            status.widthAnchor.constraint(equalTo: hero.widthAnchor),
            extraStatus.widthAnchor.constraint(equalTo: hero.widthAnchor),
            scopeHeading.widthAnchor.constraint(equalTo: scope.widthAnchor),
            output.widthAnchor.constraint(equalTo: scope.widthAnchor)
        ])
    }

    private func configureColumn(_ column: NSStackView, spacing: CGFloat) {
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = spacing
    }

    func setCompact(_ compact: Bool) {
        title.font = .systemFont(ofSize: compact ? 25 : 32, weight: .bold)
    }

    func render(language: UILanguage, status message: UIMessage, body: UIMessage, hasInput: Bool,
                snapshot: OrchardZipDisplaySnapshot?, instruction: String?, instructionPending: UIMessage?,
                extra: UIMessage?, thoroughInFlight: Bool) {
        func label(_ field: NSTextField, _ text: String) {
            field.stringValue = text
            field.setAccessibilityLabel(text)
        }
        label(title, UIM("zip.home.title", "AIに渡す前に、ZIPを確認").render(language))
        label(description, UIM("zip.description", "外側ZIPの構造・既知SHA・本文を確認し、対応する内側ZIPの本文を1階層まで検査します。展開保存・実行・外部送信は行いません。").render(language))
        label(scopeTitle, UIM("zip.home.scope", "照合の範囲").render(language))
        for (button, copy) in [
            (choose as NSButton, UIM("zip.select", "ZIPを選んで照合")),
            (cancel, thoroughInFlight ? UIM("zip.thorough.cancel", "検査を中止") : UIM("zip.cancel", "照合を中止")),
            (repeatCurrent, UIM("zip.repeat", "通常で再照合")),
            (showResult, UIM("zip.pearl.open", "検査結果を表示"))
        ] {
            button.title = copy.render(language)
            button.setAccessibilityLabel(button.title)
        }
        cancel.isHidden = !cancel.isEnabled
        repeatCurrent.isHidden = !hasInput || cancel.isEnabled
        showResult.isHidden = snapshot == nil
        secondaryActions.isHidden = cancel.isHidden && repeatCurrent.isHidden && showResult.isHidden
        extraStatus.isHidden = extra == nil
        label(extraStatus, extra?.render(language) ?? "")
        instructionSummary.isHidden = !hasInput
        if let snapshot {
            let copy = OrchardZipResultCopy(snapshot: snapshot)
            label(status, copy.headline.render(language) + "\n" + copy.file.render(language))
            label(output, Self.baseline.render(language))
        } else {
            label(status, message.render(language))
            label(output, body.render(language))
        }
        let detected = instruction == "DETECTED"
        instructionIcon.isHidden = !detected
        instructionResult.font = .systemFont(ofSize: detected ? 17 : 13, weight: .semibold)
        instructionResult.textColor = detected ? .systemRed : .labelColor
        if let snapshot, let scan = snapshot.evidence.instructionScope {
            instructionResult.textColor = scan.status.textColor(ink: .labelColor, warning: .systemRed)
            label(instructionResult, OrchardZipResultCopy(snapshot: snapshot).instruction.render(language))
            return
        }
        let instructionCopy: UIMessage
        switch instruction {
        case "DETECTED": instructionCopy = UIM("zip.instruction.detected", "疑わしい指示を検出しました")
        case "NOT_DETECTED": instructionCopy = UIM("zip.instruction.not_detected", "対象規則内で疑わしい指示は検出されませんでした")
        case "NO_TEXT_IN_SCOPE": instructionCopy = UIM("zip.scope.noText", "指示検査の対象となるテキストはありません")
        default:
            let scoped = snapshot.flatMap { result in
                result.evidence.presentation.map { _ in OrchardZipResultCopy(snapshot: result).instruction }
            }
            instructionCopy = instructionPending ?? scoped ?? snapshot?.zeroDocumentReason ??
                UIM("zip.instruction.incomplete", "指示の検査を完了できませんでした")
        }
        label(instructionResult, instructionCopy.render(language))
    }
}

@MainActor final class OrchardZipController: NSObject {
    let home = OrchardZipHomeControls()
    private var statusMessage = OrchardZipHomeControls.idleStatus
    private var bodyMessage = OrchardZipHomeControls.baseline
    private var instructionStatus: String?
    private var instructionPending: UIMessage? = OrchardZipHomeControls.idleInstruction
    private struct AcceptedInspection {
        let snapshot: OrchardZipDisplaySnapshot
        let receipt: Data
    }
    private var accepted: AcceptedInspection? {
        didSet { home.onFrameChange?(accepted?.snapshot.frameTone ?? .pearl) }
    }
    private var lastURL: URL?
    private var activeJob: OrchardZipJob?
    private var extraStatus: UIMessage?
    private var workerCleanupVerified = true
    private var canStartInspection: Bool { activeJob == nil && workerCleanupVerified }
    private var terminationReply: ((Bool) -> Void)?
    private var resultSheet: OrchardZipResultSheet?
    var onLanguageChange: (() -> Void)?

    override init() {
        super.init()
        home.choose.target = self
        home.choose.action = #selector(selectZip)
        home.cancel.target = self
        home.cancel.action = #selector(cancelInspection)
        home.repeatCurrent.target = self
        home.repeatCurrent.action = #selector(reinspectNormal)
        home.showResult.target = self
        home.showResult.action = #selector(presentAcceptedResult)
        renderLanguage()
    }

    @objc private func selectZip() {
        guard canStartInspection else { return }
        let picker = NSOpenPanel()
        OrchardPearlArt.applyAppearance(to: picker)
        picker.message = UIL("zip.select_prompt", "照合するZIPを1つ選択してください")
        picker.prompt = UIL("zip.inspect_selected", "このZIPを照合")
        picker.allowedContentTypes = [.zip]
        picker.canChooseDirectories = false
        picker.allowsMultipleSelection = false
        picker.begin { [weak self] result in
            guard result == .OK, let url = picker.url else { return }
            self?.inspect(url)
        }
    }

    @objc private func reinspectNormal() { if let url = lastURL { inspect(url) } }
    @objc private func reinspectExpired() { if let url = lastURL { inspect(url, mode: .expired) } }
    @objc private func reinspectFailed() { if let url = lastURL { inspect(url, mode: .failed) } }

    private func inspect(_ url: URL, mode: OrchardWarehouseMode = .live, expectedSHA256: String? = nil) {
        guard canStartInspection else { return }
        let targets: [String]
        if let expectedSHA256 {
            guard let snapshot = accepted?.snapshot, snapshot.evidence.archiveSHA256 == expectedSHA256,
                  OrchardZipResultCopy(snapshot: snapshot).canInspectThoroughly else { return }
            targets = Self.knownTargets(snapshot)
        } else {
            accepted = nil
            extraStatus = nil
            targets = []
        }
        // A delayed picker reply may arrive while the previous result is still attached.
        if let old = resultSheet?.window, let parent = old.sheetParent {
            parent.endSheet(old)
            old.orderOut(nil)
            resultSheet = nil
        }
        lastURL = url
        let job = OrchardZipJob(url: url, mode: mode, expectedSHA256: expectedSHA256, progressTargets: targets)
        activeJob = job
        if job.thorough {
            extraStatus = Self.runningStatus(count: targets.count, remaining: targets.count)
        }
        home.choose.isEnabled = false; home.cancel.isEnabled = true
        for button in [home.repeatCurrent] { button.isEnabled = false }
        setStatus(UIM("zip.inspecting_prefix", "照合中: ") + visible(url.lastPathComponent))
        showInstructionResult(nil, pending: UIM("zip.instruction.in_progress", "指示の検査中です"))
        setBody(job.thorough
            ? UIM("zip.thorough.running", "サイズ・時間・入れ子の範囲を広げて検査しています。圧縮率の検査は有効です。")
            : UIM("zip.bounds", "ZIPは最大{p0} MiB・1,024項目。非圧縮サイズ合計は最大64 MiB。検査ワーカーは最大10秒で停止します。",
                ["p0": UIValue(OrchardZipLimits.archiveMiB)]))
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result {
                try job.run { remaining in
                    DispatchQueue.main.async { [weak self] in
                        guard let self, self.activeJob === job, !job.cancellation.requested else { return }
                        self.extraStatus = Self.runningStatus(count: job.progressTargets.count, remaining: remaining)
                        self.renderLanguage()
                    }
                }
            }
            DispatchQueue.main.async { self?.finished(job, result: result) }
        }
    }

    private static func knownTargets(_ snapshot: OrchardZipDisplaySnapshot) -> [String] {
        guard let scan = snapshot.evidence.instructionScope,
              Set(scan.archive_reasons.keys).isSubset(of: ["TOTAL_MEMBER_SIZE_LIMIT"]) else { return [] }
        let items = scan.items.filter { $0.disposition == .unread }
        guard (1...64).contains(items.count),
              items.allSatisfy({ item in
                  (0..<OrchardZipLimits.entries).contains(item.entry_index) &&
                      (item.nested_entry_index.map { (0..<OrchardZipLimits.entries).contains($0) } ?? true)
              }) else { return [] }
        return items.map { item in
            item.nested_entry_index.map { "\(item.entry_index).\($0)" } ?? String(item.entry_index)
        }
    }

    private static func runningStatus(count: Int, remaining: Int) -> UIMessage {
        let title = UIM("zip.thorough.inProgress", "追加検査中")
        guard count > 0 else { return title }
        return title + "\n" + UIM("zip.thorough.knownProgress", "未確認だった対象{p0}件を検査中（残り{p1}件）",
                                  ["p0": UIValue(count), "p1": UIValue(remaining)])
    }

    private func visible(_ text: String) -> String {
        orchardVisible(text)
    }

    private func finished(_ job: OrchardZipJob, result: Result<Data, Error>) {
        guard activeJob === job else { return }
        activeJob = nil
        workerCleanupVerified = job.resourcesQuiescent
        defer {
            if let reply = terminationReply {
                terminationReply = nil
                reply(job.resourcesQuiescent)
            }
        }
        home.choose.isEnabled = workerCleanupVerified; home.cancel.isEnabled = false
        home.repeatCurrent.isEnabled = workerCleanupVerified && lastURL != nil
        home.showResult.isEnabled = workerCleanupVerified
        guard workerCleanupVerified else {
            let message = UIM("zip.thorough.cleanupUnverified", "検査プロセスの終了を確認できませんでした。")
            if job.thorough { extraStatus = message }
            setStatus(message)
            return
        }
        if job.cancellation.requested {
            if job.thorough {
                extraStatus = UIM("zip.thorough.stopped", "追加検査を中止しました。前回の検査結果を表示しています。")
            }
            showInstructionResult(accepted?.snapshot.promptInjection)
            setStatus(UIM("zip.abort", "照合を中止しました"))
            setBody(UIM("zip.discarded", "結果は採用していません。"))
            return
        }
        do {
            let receipt = try result.get()
            let presentation = try orchardZipSnapshot(receipt: receipt, name: job.url.lastPathComponent,
                reportInspectionSourceSHA256: job.reportInspectionSourceSHA256)
            guard presentation.evidence.thorough == job.thorough,
                  job.expectedSHA256.map({ $0 == presentation.evidence.archiveSHA256 }) ?? true
            else { throw OrchardFault.result }
            extraStatus = nil
            accepted = AcceptedInspection(snapshot: presentation, receipt: receipt)
            showInstructionResult(presentation.promptInjection)
            renderLanguage()
            showAcceptedResult(animateFrame: true)
        } catch {
            if job.thorough {
                extraStatus = UIM("zip.thorough.failed", "追加検査に失敗しました。前回の検査結果を表示しています。")
            }
            showInstructionResult(accepted?.snapshot.promptInjection)
            setStatus(UIM("zip.scope.unavailable", "ZIPの検査に失敗しました"))
            if let limit = error as? OrchardZipSizeLimit {
                setBody(limit.guidance)
                return
            }
            setBody(UIM("zip.failure_prefix", "ZIPの上限・入力の変更・実行環境または検査結果を確認できませんでした。\n安全・不一致とは判定しません。\n詳細: ") + visible(String(describing: error)))
        }
    }

    @objc private func presentAcceptedResult() {
        showAcceptedResult(animateFrame: false)
    }

    private func showAcceptedResult(animateFrame: Bool) {
        guard canStartInspection, let prior = accepted, resultSheet == nil, let parent = home.hero.window,
              parent.isVisible, parent.attachedSheet == nil else { return }
        let sheet = OrchardZipResultSheet(snapshot: prior.snapshot, preference: .shared,
            inspectThoroughly: { [weak self] in
                self?.startThoroughInspection(from: prior.receipt)
            },
            reportIsCurrent: { [weak self] offer in
                guard let self, self.activeJob == nil else { return false }
                return self.accepted?.snapshot.reportOffer === offer
            }) { [weak self] in
            self?.onLanguageChange?()
        }
        resultSheet = sheet
        sheet.present(in: parent, returnFocusTo: home.showResult, animateFrame: animateFrame) { [weak self, weak sheet] in
            guard let self, let sheet, self.resultSheet === sheet else { return }
            self.resultSheet = nil
        }
    }

    private func startThoroughInspection(from receipt: Data) {
        guard canStartInspection, let url = lastURL, let prior = accepted, prior.receipt == receipt else { return }
        inspect(url, expectedSHA256: prior.snapshot.evidence.archiveSHA256)
    }

    private func showInstructionResult(_ result: String?, pending: UIMessage? = nil) {
        instructionStatus = result
        instructionPending = pending
        renderLanguage()
    }


    @objc private func cancelInspection() {
        requestCancellation("HUMAN_CANCEL")
    }

    private func requestCancellation(_ reason: String) {
        guard let job = activeJob, !job.cancellation.requested else { return }
        job.cancellation.request(reason)
        home.cancel.isEnabled = false
        if job.thorough { extraStatus = UIM("zip.thorough.stopping", "追加検査を中止中") }
        setStatus(UIM("zip.cancel_wait", "中止と子プロセスの終了を確認中"))
    }

    func cancelForTermination() { requestCancellation("APP_TERMINATION") }

    func deferTermination(_ reply: @escaping (Bool) -> Void) -> Bool {
        guard !canStartInspection else { return false }
        guard activeJob != nil else {
            DispatchQueue.main.async { reply(false) }
            return true
        }
        terminationReply = reply
        cancelForTermination()
        setStatus(UIM("zip.quit_wait", "検査を中止し、子プロセスの終了を確認してからアプリを終了します"))
        return true
    }

    private func setStatus(_ message: UIMessage) {
        statusMessage = message; renderLanguage()
    }
    private func setBody(_ message: UIMessage) {
        bodyMessage = message; renderLanguage()
    }
    func renderLanguage() {
        home.render(language: UILanguagePreference.shared.language,
                    status: statusMessage, body: bodyMessage, hasInput: lastURL != nil,
                    snapshot: activeJob == nil ? accepted?.snapshot : nil,
                    instruction: instructionStatus, instructionPending: instructionPending,
                    extra: extraStatus, thoroughInFlight: activeJob?.thorough == true)
    }
}

private struct OrchardZipResultCopy {
    let snapshot: OrchardZipDisplaySnapshot
    var evidence: R1ZipReportEvidence { snapshot.evidence }
    var threat: R1ThreatIntelligence { evidence.threat }
    var foundInstruction: Bool { snapshot.promptInjection == "DETECTED" }
    var matchedSHA: Bool { threat.status == "KNOWN_HASH_MATCH" }
    var needsPause: Bool { foundInstruction || matchedSHA || evidence.hasImportantStructureAnomaly }
    private var displayUnverifiedCount: Int { evidence.scannedBodiesWithU0008.count }
    private var backspaceDisplayWarning: UIMessage {
        UIM("zip.scope.backspaceDisplay", "指示本文は検査済み。ただし制御文字 U+0008 により表示上の解釈は未確認。")
    }
    var incomplete: Bool {
        if let scan = evidence.instructionScope {
            return scan.hasUnread || !threat.coverage.complete || threat.status == "DB_NOT_UPDATED"
        }
        return evidence.inspectionStatus == "UNKNOWN" || snapshot.promptInjection == "UNINSPECTABLE" ||
            threat.status == "UNINSPECTABLE" || threat.status == "DB_NOT_UPDATED" || !threat.coverage.complete
    }

    private var shouldHoldSharing: Bool {
        // Current receipts separate inspection coverage from the engine's handoff gate.
        let inspectionOnHold = evidence.inspectionGate.map { $0 == .hold } ?? (evidence.gate == "HOLD")
        return needsPause || incomplete || inspectionOnHold
    }

    private var unscannedItems: UIMessage? {
        guard evidence.listedEntries == 0, evidence.instructionScope?.archive_reasons["ENTRY_COUNT_LIMIT"] != nil
            else { return nil }
        return UIM("zip.scope.unscannedItems", "未走査の項目あり（総数未確定）")
    }

    private func reason(_ code: String, useArchiveContext: Bool) -> UIMessage {
        switch code {
        case "TEXT_BODY_NOT_APPLICABLE":
            return UIM("zip.mint.reason.noBody", "既知の非テキスト形式・メタデータ・空ファイル")
        case "NON_PLAIN_TEXT_DOCUMENT_UNINSPECTED":
            return UIM("zip.scope.reason.pdfUnchecked", "PDFなどの本文は未検査")
        case "EXECUTABLE_BODY_UNINSPECTED":
            return UIM("zip.scope.reason.executable", "実行形式の中身が対象外")
        case "SQLITE_BODY_UNINSPECTED":
            return UIM("zip.scope.reason.sqlite", "SQLiteデータベースの内容が対象外")
        case "OPAQUE_BINARY_UNINSPECTED":
            return UIM("zip.scope.reason.opaqueOutOfScope", "形式不明のバイナリ（対象外）")
        case "ENCRYPTED_ENTRY_UNSUPPORTED":
            return UIM("zip.scope.reason.encryptedOutOfScope", "暗号化中の本文は読めません")
        case "UNSUPPORTED_ARCHIVE_BODY_OUT_OF_SCOPE":
            return UIM("zip.scope.reason.unhandledArchive", "この形式の内部は未検査")
        case "TEXT_UNREADABLE_UnicodeDecodeError":
            return UIM("zip.scope.reason.encoding", "対応する文字コードで読めない文書")
        case "TEXT_CONTROL_OR_FORMAT_CHARACTER":
            return UIM("zip.scope.reason.characters", "本文の見え方に影響し得る文字")
        case "NESTED_FORMAT_UNSUPPORTED":
            if useArchiveContext, evidence.presentation != nil,
               evidence.scope?.nested.contains(where: \.archiveFormatUnconfirmed) == true {
                return UIM("zip.scope.reason.innerHeader", "内側アーカイブの形式を確認できませんでした")
            }
            return UIM("zip.scope.reason.innerFormat", "対応外の内側アーカイブ形式")
        case "NESTED_CONTENT_UNRESOLVED":
            return UIM("zip.scope.reason.innerPartial", "検査の一部が未完了の内側アーカイブ")
        case "LINK_OR_SPECIAL_FILE_UNSUPPORTED":
            return UIM("zip.scope.reason.links", "リンク・特殊ファイル")
        case "INTERNAL_LINK_REFERENCE":
            return UIM("zip.scope.reason.internalLink", "ZIP内部を指すリンク")
        case "ZIP_LINK_TARGET_EXTERNAL":
            return UIM("zip.scope.reason.externalLink", "リンクがZIPの外を参照")
        case "ZIP_LINK_TARGET_CYCLE":
            return UIM("zip.scope.reason.linkCycle", "リンク参照が循環")
        case "ZIP_LINK_PATH_CONFLICT":
            return UIM("zip.scope.reason.linkConflict", "リンクのパスがディレクトリと競合")
        case "ZIP_LINK_TARGET_UNRESOLVED":
            return UIM("zip.scope.reason.linkUnresolved", "リンク先をZIP内の項目に結び付けられない")
        case "ZIP_LINK_TARGET_INVALID":
            return UIM("zip.scope.reason.linkInvalid", "リンクに無効な参照先が格納されている")
        case "ZIP_LINK_TARGET_SIZE_LIMIT":
            return UIM("zip.scope.reason.linkSize", "リンク先の読取上限（512バイト）")
        case "ZIP_LINK_CHAIN_LIMIT":
            return UIM("zip.scope.reason.linkChain", "リンクの連鎖上限（16参照）")
        case "NESTED_DEPTH_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughDepth", "入れ子の深さ上限（内側4階層まで）")
                : UIM("zip.scope.reason.innerDepthLimit", "入れ子の深さ上限（内側1階層まで）")
        case "NESTED_ARCHIVE_SIZE_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughArchiveSize", "内側アーカイブの本文上限（1件16 MiB）")
                : UIM("zip.scope.reason.innerSize", "内側アーカイブの本文検査上限（1件 4 MiB）")
        case "MEMBER_READ_BUDGET_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughReadBudget", "展開読取の共有予算（128 MiB）")
                : UIM("zip.scope.reason.readBudget", "展開読取の共有予算（64 MiB）")
        case "TOTAL_MEMBER_SIZE_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughTotalSize", "申告された非圧縮サイズの合計が128 MiBを超過")
                : UIM("zip.scope.reason.declaredSize", "申告された非圧縮サイズの合計が 64 MiB を超過")
        case "TEXT_BYTE_LIMIT":
            if evidence.thorough { return UIM("zip.scope.reason.thoroughTextSize", "指示文書1件の本文上限（16 MiB）") }
            if evidence.instructionScope?.checked_members != nil {
                return UIM("zip.scope.reason.textMemberLimit", "指示文書1件の本文上限（4 MiB）")
            }
            return UIM("zip.scope.reason.textBudget", "本文読取の上限（1件 4 MiB、合計 32 MiB）")
        case "TEXT_TOTAL_BUDGET_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughTextTotal", "指示文書の本文読取予算（合計64 MiB）")
                : UIM("zip.scope.reason.textTotalLimit", "指示文書の本文読取予算（合計32 MiB）")
        case "MEMBER_SIZE_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughMemberSize", "項目1件の非圧縮サイズ上限（32 MiB）")
                : UIM("zip.scope.reason.memberSizeLimit", "項目1件の非圧縮サイズ上限（16 MiB）")
        case "EXPANSION_RATIO_LIMIT", "NESTED_EXPANSION_RATIO_LIMIT":
            return UIM("zip.scope.reason.ratioLimit", "展開比の上限（100倍）")
        case "ENTRY_COUNT_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughEntryLimit", "ZIP項目数の上限（4,096件）")
                : UIM("zip.scope.reason.entryLimit", "ZIP項目数の上限（1,024件）")
        case "CENTRAL_DIRECTORY_SIZE_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughDirectory", "ZIP項目一覧のサイズ上限（2 MiB）")
                : UIM("zip.scope.reason.directoryLimit", "ZIP項目一覧のサイズ上限（1 MiB）")
        case "NESTED_DIRECTORY_BUDGET_LIMIT":
            return evidence.thorough
                ? UIM("zip.scope.reason.thoroughInnerDirectory", "入れ子を含む項目一覧の共有予算（4,096件・2 MiB）")
                : UIM("zip.scope.reason.innerDirectoryLimit", "入れ子を含むZIP項目一覧の共有予算（1,024件・1 MiB）")
        case "PATH_SIZE_LIMIT":
            return UIM("zip.scope.reason.pathLimit", "パス長の上限（512バイト。超過分は省略）")
        case "UNSAFE_OR_AMBIGUOUS_PATH":
            return UIM("zip.scope.reason.unsafePath", "格納パスが不正、または展開先を一意に確認できない")
        case "ARCHIVE_SIZE_LIMIT":
            return UIM("zip.scope.reason.archiveSizeLimit", "ZIPファイルのサイズ上限")
        case "DB_LOOKUP_FAILED":
            return UIM("zip.scope.reason.lookup", "既知SHAデータベースで照合に失敗")
        case "INPUT_UNAVAILABLE", "INPUT_CHANGED_DURING_READ":
            return UIM("zip.scope.reason.input", "検査元のZIPを途中までしか確認できないか、読み取れない状態")
        case let value where value.hasSuffix("_DEADLINE"):
            return UIM("zip.scope.reason.time", "検査の制限時間")
        case let value where value.hasSuffix("_LIMIT"):
            return UIM("zip.scope.reason.limit", "サイズ・件数・読取り予算の上限")
        case let value where value.hasPrefix("TAR_STRUCTURE_") || value.hasPrefix("GZIP_STRUCTURE_"):
            return UIM("zip.scope.reason.streamStructure", "tar・gzipの構造または整合性に異常")
        case let value where value.hasPrefix("MALFORMED_") || value.hasSuffix("_MISMATCH") ||
            value.hasPrefix("MEMBER_STREAM_") || value.hasPrefix("LOCAL_HEADER_") ||
            value.hasPrefix("ZIP_UNREADABLE_") || value.hasPrefix("MEMBER_SPAN_"):
            return UIM("zip.scope.reason.structure", "ZIPの構造または整合性を確認できない項目")
        default: return .verbatim(orchardVisible(code))
        }
    }

    private func reasonLines(_ counts: [String: Int], useArchiveContext: Bool = true) -> [UIMessage] {
        counts.sorted { $0.key < $1.key }.prefix(16).map { code, count in
            UIM("zip.scope.reason.count", "{p0} · {p1} 件", [
                "p0": UIValue(reason(code, useArchiveContext: useArchiveContext)), "p1": UIValue(count)
            ])
        }
    }

    var nestedArchivePriority: UIMessage? {
        let paths = evidence.nestedArchivePaths
        guard evidence.instructionScope == nil, incomplete, !needsPause, !paths.isEmpty,
              evidence.presentation != .outOfScope else { return nil }
        let count = ["p0": UIValue(paths.count)]
        if paths.allSatisfy({ $0.lowercased().hasSuffix(".zip") }) {
            return UIM("zip.pearl.innerZipPriority", "中身を確認できなかった内側のZIP {p0} 件", count)
        }
        return UIM("zip.pearl.innerArchivePriority", "中身を確認できなかった内側のアーカイブ {p0} 件", count)
    }

    var canInspectThoroughly: Bool {
        guard !evidence.thorough, !needsPause, let scan = evidence.instructionScope else { return false }
        let limits: Set<String> = ["NESTED_DEPTH_LIMIT", "NESTED_ARCHIVE_SIZE_LIMIT", "MEMBER_READ_BUDGET_LIMIT",
            "TEXT_BYTE_LIMIT", "TEXT_TOTAL_BUDGET_LIMIT", "TOTAL_MEMBER_SIZE_LIMIT", "MEMBER_SIZE_LIMIT",
            "NESTED_DIRECTORY_BUDGET_LIMIT", "CENTRAL_DIRECTORY_SIZE_LIMIT", "ENTRY_COUNT_LIMIT"]
        return scan.unreadReasons.keys.contains { limits.contains($0) || $0.hasSuffix("_DEADLINE") }
    }

    var headline: UIMessage {
        if let scan = evidence.instructionScope {
            if foundInstruction || matchedSHA { return UIM("zip.action.decision.doNotShare", "渡さないで（検出あり）") }
            if evidence.hasImportantStructureAnomaly {
                return UIM("zip.action.mac.structurePause", "構造上の異常があるため、展開は見送ってください。")
            }
            if displayUnverifiedCount > 0 { return UIM("zip.pearl.pause", "AIへの受け渡しを見送ってください") }
            if scan.checked_files == 0 && scan.hasUnread {
                let firstReason = scan.unreadReasons.keys.sorted().first ?? "INPUT_UNAVAILABLE"
                let cause = ["p0": UIValue(reason(firstReason, useArchiveContext: true))]
                return canInspectThoroughly
                    ? UIM("zip.action.decision.zeroThorough", "本文未検査（{p0}）。AIへの受け渡しを保留し、［最後まで調べる］で確認してください。", cause)
                    : UIM("zip.action.decision.zeroHold", "本文未検査（{p0}）。AIへの受け渡しを保留し、［詳細を確認］で対象を確認してください。", cause)
            }
            if scan.hasUnread {
                let count = scan.unreadCount
                let subject = count > 0
                    ? UIM("zip.action.decision.uncheckedItems", "指示として読まれる可能性がある{p0}件", ["p0": UIValue(count)])
                    : UIM("zip.action.decision.uncheckedArchive", "指示検査の一部")
                return canInspectThoroughly
                    ? UIM("zip.action.decision.thoroughChoice",
                        "{p0}が未検査です。AIへの受け渡しを保留し、［最後まで調べる］で確認してください。",
                        ["p0": UIValue(subject)])
                    : UIM("zip.action.decision.informChoice",
                        "{p0}が未検査です。AIへの受け渡しを保留し、［詳細を確認］で理由を確認してください。",
                        ["p0": UIValue(subject)])
            }
            if shouldHoldSharing { return UIM("zip.pearl.pause", "AIへの受け渡しを見送ってください") }
            return instruction
        }
        switch evidence.presentation {
        case .detected: return foundInstruction ? instruction : sha
        case .checkFailed: return UIM("zip.scope.checkFailed", "検査に失敗した項目があります")
        case .partial: return UIM("zip.scope.scopeLimited", "検査範囲に制約があります")
        case .outOfScope: return UIM("zip.scope.formatExcluded", "本文検査の対象外形式が含まれています")
        case .complete, nil: break
        }
        if needsPause { return UIM("zip.pearl.pause", "AIへの受け渡しを見送ってください") }
        if evidence.scope != nil && incomplete { return UIM("zip.scope.partial", "未確認の範囲を保留しました") }
        if incomplete { return UIM("zip.pearl.incomplete", "確認できなかった項目があります") }
        if snapshot.promptInjection == "NO_TEXT_IN_SCOPE" { return UIM("zip.scope.noText", "指示検査の対象となるテキストはありません") }
        return UIM("zip.pearl.scoped", "検査した範囲で該当項目は見つかりませんでした")
    }
    var file: UIMessage { .verbatim(orchardVisible(snapshot.name)) }
    var instruction: UIMessage {
        if let scan = evidence.instructionScope {
            switch scan.status {
            case .noFindings: return UIM("zip.mint.noFindings", "指示文書の検査範囲内で所見なし")
            case .detected: return UIM("zip.instruction.detected", "疑わしい指示を検出しました")
            case .incomplete:
                if displayUnverifiedCount > 0, scan.unreadCount == displayUnverifiedCount, scan.archive_reasons.isEmpty {
                    return backspaceDisplayWarning
                }
                return UIM("zip.mint.incomplete", "指示文書の検査に未確認範囲があります")
            case .noTargets: return UIM("zip.scope.noText", "指示検査の対象となるテキストはありません")
            }
        }
        switch snapshot.promptInjection {
        case "DETECTED": return UIM("zip.instruction.detected", "疑わしい指示を検出しました")
        case "NOT_DETECTED": return UIM("zip.pearl.noInstruction", "対象規則内で検出なし")
        case "NO_TEXT_IN_SCOPE": return UIM("zip.scope.noText", "指示検査の対象となるテキストはありません")
        default:
            if evidence.presentation == .outOfScope || evidence.presentation == .partial {
                if evidence.textFilesRead + (evidence.scope?.nestedTextFiles ?? 0) > 0 {
                    return UIM("zip.scope.checkedText", "確認済みの本文では対象規則の検出なし")
                }
                return UIM("zip.scope.noCheckedText", "指示を検査できた本文は0件です")
            }
            return UIM("zip.instruction.incomplete", "指示の検査を完了できませんでした")
        }
    }
    var sha: UIMessage {
        switch threat.status {
        case "KNOWN_HASH_MATCH": return UIM("zip.pearl.shaMatch", "ZIP内のファイルが対象DBの既知SHAに一致しました")
        case "NO_MATCH_IN_COVERED_DB": return UIM("zip.pearl.shaNoMatch", "対象DB内に一致なし")
        case "NO_ITEMS_IN_SCOPE": return UIM("zip.scope.shaNotApplicable", "外側ZIPにSHA照合の対象ファイルはありません")
        case "DB_NOT_UPDATED": return UIM("sha.db_unverified", "DBの更新未確認。不一致を判定できません")
        default: return UIM("zip.pearl.shaIncomplete", "照合を完了できない項目があります")
        }
    }
    var actionGuidance: [(title: UIMessage, body: [UIMessage])] {
        [
            (UIM("zip.action.mac.title", "Macで展開・閲覧"), macGuidance),
            (UIM("zip.action.ai.title", "AIへ渡す"), aiGuidance),
            (UIM("zip.action.run.title", "プログラムを実行"), executionGuidance),
        ]
    }

    private func scopePath(_ index: Int, nested: String? = nil) -> String {
        let outer = threat.entries.first { $0.entry_index == index }?.path ?? snapshot.name
        return [outer, nested].compactMap { $0 }.map(orchardVisible).joined(separator: " / ")
    }

    private func itemLine(path: String, reason value: UIMessage) -> UIMessage {
        UIM("zip.action.evidence.item", "{p0} · {p1}", ["p0": UIValue(path), "p1": UIValue(value)])
    }

    var firstActionEvidence: [UIMessage] {
        guard let scan = evidence.instructionScope else { return [] }
        let display = evidence.scannedBodiesWithU0008.min().map {
            [itemLine(path: scopePath($0), reason: backspaceDisplayWarning)]
        } ?? []
        guard needsPause else { return display }
        var lines: [UIMessage] = []
        if let finding = evidence.findings.first {
            lines.append(UIM("zip.action.evidence.finding", "{p0} · {p1}行 · {p2}", [
                "p0": UIValue(visibleFindingPath(finding.path)), "p1": UIValue(finding.line),
                "p2": UIValue(Self.findingCategory(finding.category))
            ]))
        }
        if let match = threat.matches.first {
            lines.append(itemLine(path: scopePath(match.entry_index), reason: sha))
        }
        for item in scan.items where item.disposition == .unread {
            let nestedHeader = item.reasons["NESTED_FORMAT_UNSUPPORTED"] != nil &&
                evidence.scope?.nested.contains(where: { $0.entry_index == item.entry_index &&
                    ($0.kind == "ZIP" || $0.kind == "WHEEL") && $0.archiveFormatUnconfirmed }) == true
            let codes = item.reasons.keys.filter { R1ZipScopeDetail.isStructuralAnomaly($0) ||
                ($0 == "NESTED_FORMAT_UNSUPPORTED" && nestedHeader) }.sorted()
            for code in codes {
                lines.append(itemLine(path: scopePath(item.entry_index, nested: item.nested_member_path),
                                      reason: reason(code, useArchiveContext: true)))
            }
        }
        for code in scan.archive_reasons.keys.sorted() where R1ZipScopeDetail.isStructuralAnomaly(code) {
            lines.append(itemLine(path: orchardVisible(snapshot.name), reason: reason(code, useArchiveContext: true)))
        }
        return lines + display
    }

    private func visibleFindingPath(_ raw: String) -> String {
        raw.components(separatedBy: " / ").map(orchardVisible).joined(separator: " / ")
    }

    private var macGuidance: [UIMessage] {
        let structure: UIMessage
        switch evidence.scope?.structure_status {
        case "CHECKED":
            structure = UIM("zip.action.mac.checked", "外側ZIPの構造を静的に確認済み。")
        case "INCOMPLETE":
            structure = UIM("zip.action.mac.incomplete", "外側ZIPの静的構造検査に未確認あり。")
        default:
            structure = UIM("zip.action.mac.unrecorded", "外側ZIPの構造検査結果は未記録。")
        }
        var lines = [structure, UIM("zip.action.mac.limit", "展開・閲覧の安全性は未判定です。")]
        if evidence.hasImportantStructureAnomaly {
            lines.append(UIM("zip.action.mac.structurePause", "構造上の異常があるため、展開は見送ってください。"))
        }
        if matchedSHA {
            lines.append(UIM("zip.action.mac.shaPause", "一致ファイルの開封は見送ってください。"))
        }
        return lines
    }

    private func unreadGuidance(_ scan: R1InstructionScope) -> UIMessage {
        let bodyUnread = scan.unreadCount - displayUnverifiedCount
        let body: UIMessage
        if !scan.archive_reasons.isEmpty && bodyUnread == 0 {
            body = UIM("zip.action.ai.archiveUnread", "ZIP全体に未確認あり")
        } else if displayUnverifiedCount > 0 {
            body = UIM("zip.action.ai.bodyUnread", "本文未検査{p0}件", ["p0": UIValue(bodyUnread)])
        } else {
            body = UIM("zip.action.ai.unread", "未確認{p0}件", ["p0": UIValue(bodyUnread)])
        }
        guard displayUnverifiedCount > 0 else { return body }
        return body + " ／ " + UIM("zip.action.ai.displayUnverified", "表示上の解釈未確認{p0}件",
                                    ["p0": UIValue(displayUnverifiedCount)])
    }

    private var aiGuidance: [UIMessage] {
        let hold = UIM("zip.action.ai.defer", "添付を保留し、「詳細を確認」。")
        guard let scan = evidence.instructionScope else {
            return [instruction, shouldHoldSharing
                ? hold
                : UIM("zip.action.ai.source", "添付前に送信元と用途を確認。")]
        }
        let scanned = scan.checked_files + displayUnverifiedCount
        let checked = UIM("zip.action.ai.checked", "指示文書{p0}件、範囲内で所見なし。", ["p0": UIValue(scanned)])
        let status: UIMessage
        switch scan.status {
        case .noFindings:
            status = checked
        case .incomplete:
            if displayUnverifiedCount > 0, scan.unreadCount == displayUnverifiedCount, scan.archive_reasons.isEmpty {
                status = checked
            } else {
                status = scanned == 0
                    ? UIM("zip.scope.noCheckedText", "指示を検査できた本文は0件です")
                    : UIM("zip.action.ai.incomplete", "指示文書{p0}件を確認。検査未完了。", ["p0": UIValue(scanned)])
            }
        case .detected:
            status = UIM("zip.action.ai.detected", "疑わしい指示を検出（所見{p0}件）。", ["p0": UIValue(evidence.findings.count)])
        case .noTargets:
            status = UIM("zip.action.ai.noTargets", "指示文書の対象なし。")
        }

        let codes = Set(scan.items.filter { $0.disposition == .excluded }.flatMap { $0.reasons.keys })
        let formats = [
            ("NON_PLAIN_TEXT_DOCUMENT_UNINSPECTED", UIM("zip.action.format.pdf", "PDF")),
            ("EXECUTABLE_BODY_UNINSPECTED", UIM("zip.action.format.executable", "実行形式")),
            ("SQLITE_BODY_UNINSPECTED", UIM("zip.action.format.sqlite", "SQLite")),
            ("OPAQUE_BINARY_UNINSPECTED", UIM("zip.action.format.opaque", "バイナリ")),
            ("UNSUPPORTED_ARCHIVE_BODY_OUT_OF_SCOPE", UIM("zip.action.format.archive", "未対応アーカイブ")),
            ("ENCRYPTED_ENTRY_UNSUPPORTED", UIM("zip.action.format.encrypted", "暗号化")),
            ("INTERNAL_LINK_REFERENCE", UIM("zip.action.format.internalLinks", "ZIP内部リンク")),
            ("NESTED_FORMAT_UNSUPPORTED", UIM("zip.action.format.archive", "未対応アーカイブ")),
            ("TEXT_BODY_NOT_APPLICABLE", UIM("zip.action.format.assets", "非テキスト等")),
        ].compactMap { codes.contains($0.0) ? $0.1 : nil }
        let count = UIValue(scan.excludedCount)
        let excluded: UIMessage
        if let first = formats.first {
            let names = formats.dropFirst().reduce(first) { $0 + " / " + $1 }
            excluded = UIM("zip.action.ai.excludedFormats", "対象外{p0}件（{p1}）", ["p0": count, "p1": UIValue(names)])
        } else {
            excluded = UIM("zip.action.ai.excluded", "対象外{p0}件", ["p0": count])
        }

        var lines = [status, unscannedItems ?? (excluded + " ／ " + unreadGuidance(scan))]
        if threat.coverage.uninspectable_files > 0 {
            lines.append(UIM("zip.action.ai.shaUnchecked", "既知SHA未照合 {p0}件（別の検査）",
                ["p0": UIValue(threat.coverage.uninspectable_files)]))
        }
        if threat.status == "DB_NOT_UPDATED" { lines.append(sha) }
        if needsPause && foundInstruction {
            lines.append(UIM("zip.action.ai.staticFinding", "静的な規則に一致しました。文脈と意図は未判定です。"))
        }
        if evidence.findingDetailsTruncated {
            lines.append(UIM("zip.action.ai.moreFindings", "表示上限を超える所見もあります。"))
        }
        if codes.contains("ENCRYPTED_ENTRY_UNSUPPORTED") {
            lines.append(UIM("zip.action.ai.encrypted", "暗号化されたままなら本文の指示が読まれるリスクは低いです。復号後の内容は未検査です。"))
        }
        if shouldHoldSharing { lines.append(hold) }
        return lines
    }

    private var executionGuidance: [UIMessage] {
        var lines = [
            UIM("zip.action.run.limit", "実行の安全性は未検査です。"),
            UIM("zip.action.run.mint", "ミントは指示文書の範囲表示です。実行の可否は別途確認してください。"),
        ]
        if matchedSHA {
            lines.append(UIM("zip.action.run.shaPause", "一致ファイルの実行は見送ってください。"))
        }
        return lines
    }

    var archiveSize: UIMessage {
        UIM("zip.pearl.archiveSize", "入力サイズ {p0} バイト", ["p0": UIValue(evidence.archiveBytes)])
    }
    var textCoverage: UIMessage {
        if let scan = evidence.instructionScope {
            let scanned = scan.checked_files + displayUnverifiedCount
            let checked = UIM("zip.mint.checkedCount", "指示文書 {p0} 件確認", ["p0": UIValue(scanned)])
            if let unscannedItems {
                return checked + " ／ " + unscannedItems
            }
            if displayUnverifiedCount > 0 {
                let excluded = UIM("zip.action.ai.excluded", "対象外{p0}件", ["p0": UIValue(scan.excludedCount)])
                return checked + " ／ " + excluded + " ／ " + unreadGuidance(scan)
            }
            return UIM("zip.mint.coverage", "指示文書 {p0} 件確認 ／ 対象外 {p1} 件 ／ 未検査 {p2} 件", [
                "p0": UIValue(scan.checked_files), "p1": UIValue(scan.excludedCount), "p2": UIValue(scan.unreadCount)
            ])
        }
        if let scope = evidence.scope {
            return snapshot.outerTextCoverage(scope)
        }
        let counts = UIM("zip.pearl.textCoverage", "列挙 {p0} 項目 ／ 読み取った文書 {p1} 件", [
            "p0": UIValue(evidence.listedEntries), "p1": UIValue(evidence.textFilesRead)
        ])
        guard let hashOnly = evidence.hashOnlyFiles, let unread = evidence.uninspectedFiles else { return counts }
        return counts + "\n" + UIM("zip.pearl.textScope", "SHA照合のみ {p0} 件 ／ 本文の対象外・未確認 {p1} 件", [
            "p0": UIValue(hashOnly), "p1": UIValue(unread)
        ])
    }
    var shaCoverage: UIMessage {
        if unscannedItems != nil {
            return UIM("zip.pearl.shaUnlisted", "項目一覧が未取得のため、既知SHAは未照合。")
        }
        return UIM("zip.pearl.shaCoverage", "SHA照合　確認済み {p0} ／ 検査不能 {p1} ／ 一致 {p2}", [
            "p0": UIValue(threat.coverage.checked_files), "p1": UIValue(threat.coverage.uninspectable_files),
            "p2": UIValue(threat.matches.count)
        ])
    }
    var heroSummary: UIMessage {
        if foundInstruction {
            return UIM("zip.pearl.findings", "検出項目 {p0} 件 ／ 検出箇所 {p1} 件", [
                "p0": UIValue(Set(evidence.findings.map(\.entryIndex)).count),
                "p1": UIValue(evidence.findings.count)])
        }
        if matchedSHA || evidence.instructionScope != nil { return shaCoverage }
        return nestedArchivePriority ?? textCoverage
    }
    var advisories: [UIMessage] {
        var messages: [UIMessage] = []
        if incomplete && evidence.scope == nil { messages.append(UIM("zip.pearl.incomplete", "確認できなかった項目があります")) }
        if evidence.instructionScope == nil {
            if evidence.presentation == .outOfScope {
                messages.append(UIM("zip.scope.wholeOnHold", "ZIP全体の判定は保留"))
            } else if evidence.gate == "HOLD" || (evidence.scope != nil && (incomplete || needsPause)) {
                messages.append(UIM("zip.pearl.hold", "検査の扱い　保留（HOLD）"))
            }
        }
        if threat.database.verification_mode != "LIVE" {
            messages.append(UIM("zip.report.simulation", "【検証】"))
        }
        switch threat.database.reason {
        case "DB_STALE":
            messages.append(UIM("sha.db.stale", "DB状態: 25時間超（参考情報）。保存済み倉庫内の一致・未一致を照合します。"))
        case "UPDATE_FAILED":
            messages.append(UIM("sha.db.failed", "DB状態: 更新失敗。既知一致は保持し、不一致は保留します。"))
        case "DB_CLOCK_INVALID":
            messages.append(UIM("sha.db.clock", "DB状態: 時刻を確認できません。不一致は保留します。"))
        default: break
        }
        return messages
    }

    func details(language: UILanguage) -> String {
        var lines: [UIMessage] = []
        let paths = Dictionary(uniqueKeysWithValues: threat.entries.map { ($0.entry_index, $0.path) })
        if let scan = evidence.instructionScope {
            if let structure = snapshot.scopeLines.first { lines.append(structure) }
            lines += [instruction, textCoverage, sha, shaCoverage,
                UIM("zip.scope.shaOuterOnly", "既知SHA照合は外側ZIPの直接メンバーが対象です。内側の本文検査と結果を分けています。"),
                .verbatim("")]
            let groups: [(R1InstructionScopeItem.Disposition, UIMessage)] = [
                (.unread, UIM("zip.mint.unreadTitle", "指示文書検査の未確認項目と理由")),
                (.excluded, UIM("zip.mint.excludedTitle", "指示文書検査の対象外項目"))
            ]
            for (disposition, title) in groups {
                let items = scan.items.filter { $0.disposition == disposition }
                let rootReasons = disposition == .unread ? scan.archive_reasons : [:]
                guard !items.isEmpty || !rootReasons.isEmpty else { continue }
                lines.append(title)
                lines += reasonLines(rootReasons)
                for item in items {
                    let components = [paths[item.entry_index], item.nested_member_path].compactMap { $0 }
                    lines.append(.verbatim(components.map { orchardVisible($0) }.joined(separator: " / ")))
                    if item.nested_entry_index == nil, evidence.scannedBodiesWithU0008.contains(item.entry_index) {
                        lines.append(backspaceDisplayWarning)
                    }
                    let unconfirmedFormat = disposition == .unread && item.reasons["NESTED_FORMAT_UNSUPPORTED"] != nil
                    lines += reasonLines(item.reasons, useArchiveContext: unconfirmedFormat)
                }
                if disposition == .unread {
                    lines += evidence.unknownDetails.filter { $0.hasPrefix("TEXT_CONTROL_OR_FORMAT_CHARACTER / ") }
                        .map { .verbatim($0) }
                }
                lines.append(.verbatim(""))
            }
        } else if let scope = evidence.scope {
            lines += snapshot.scopeLines + [
                UIM("zip.scope.shaOuterOnly", "既知SHA照合は外側ZIPの直接メンバーが対象です。内側の本文検査と結果を分けています。"),
                shaCoverage,
            ]
            lines += reasonLines(scope.blocking_reasons)
            for inner in scope.nested.sorted(by: { $0.entry_index < $1.entry_index }).prefix(24) {
                lines.append(UIM("zip.scope.innerDetail", "{p0} ／ 本文読取 {p1} 件", [
                    "p0": UIValue(orchardVisible(paths[inner.entry_index] ?? "")), "p1": UIValue(inner.text_files_read)
                ]))
                if evidence.presentation != nil, inner.archiveFormatUnconfirmed {
                    lines.append(UIM("zip.scope.reason.innerHeader", "内側アーカイブの形式を確認できませんでした"))
                } else {
                    lines += reasonLines(inner.reasons, useArchiveContext: false)
                }
            }
            lines.append(.verbatim(""))
        }
        if let priority = nestedArchivePriority {
            lines += [UIM("zip.pearl.priorityFiles", "先に確認するファイル"), priority]
            lines += evidence.nestedArchivePaths.map { .verbatim("  " + $0) }
            lines.append(.verbatim(""))
        }
        lines += [
            UIM("report.input_sha", "入力SHA256: {p0}", ["p0": UIValue(evidence.archiveSHA256)]),
            UIM("report.counts", "外側ZIPの項目 {p0} 件 ／ 本文読取 {p1} 件・{p2} バイト", [
                "p0": UIValue(evidence.listedEntries), "p1": UIValue(evidence.textFilesRead),
                "p2": UIValue(evidence.textBytesRead)
            ]),
            textCoverage,
            evidence.instructionScope == nil
                ? UIM("zip.pearl.scopeLimit", "ZIP全体の安全性は判定していません。")
                : UIM("zip.mint.safetyLimit", "ZIP全体の安全性、対象外の内容、ファイルの実行安全性は未判定です。"),
            UIM("zip.pearl.ruleLimit", "対象のテキストに既存の規則を適用します。引用も検出対象になり得ます。"), .verbatim("")
        ]
        let groups = Dictionary(grouping: evidence.findings, by: \.entryIndex)
        if !groups.isEmpty {
            lines += [UIM("zip.pearl.findings", "検出項目 {p0} 件 ／ 検出箇所 {p1} 件", [
                "p0": UIValue(groups.count), "p1": UIValue(evidence.findings.count)
            ]), UIM("zip.pearl.untrusted", "ZIP内の非信頼データ")]
            for (index, hits) in groups.sorted(by: { $0.key < $1.key }) {
                guard let first = hits.first else { continue }
                lines.append(.verbatim("#\(index)  \(first.path)"))
                for hit in hits {
                    lines.append(UIM("zip.pearl.findingLine", "  {p0}・{p1} 行目", [
                        "p0": UIValue(Self.findingCategory(hit.category)), "p1": UIValue(hit.line)
                    ]))
                    lines.append(.verbatim("  " + hit.excerpt))
                }
            }
            lines.append(.verbatim(""))
        }
        let matchingIndices = Set(threat.matches.map(\.entry_index))
        if !matchingIndices.isEmpty {
            lines += [UIM("zip.pearl.matchingFiles", "既知SHAに一致した項目"),
                      UIM("zip.pearl.untrusted", "ZIP内の非信頼データ")]
            for entry in threat.entries where matchingIndices.contains(entry.entry_index) {
                lines.append(.verbatim(orchardVisible(entry.path)))
            }
            lines.append(.verbatim(""))
        }
        if evidence.instructionScope != nil {
            if !threat.unknown_conditions.isEmpty {
                lines.append(UIM("zip.mint.shaUnreadTitle", "既知SHAを照合できなかった項目"))
                for item in threat.unknown_conditions {
                    if let index = item.entry_index, let path = paths[index] {
                        lines.append(.verbatim(orchardVisible(path)))
                    }
                    lines.append(reason(item.code, useArchiveContext: false))
                }
            }
            lines += advisories
        } else if incomplete {
            lines.append(UIM("zip.pearl.unknownReasons", "未確認の理由"))
            if let reason = snapshot.zeroDocumentReason { lines.append(reason) }
            lines += evidence.unknownDetails.map { .verbatim($0) }
            lines += threat.unknown_conditions.map { .verbatim(orchardVisible($0.code)) }
            lines += advisories
            lines.append(.verbatim(""))
        }
        return (lines + threat.presentationLines).map { $0.render(language) }.joined(separator: "\n")
    }

    fileprivate static func findingCategory(_ category: String) -> UIMessage {
        switch category {
        case "INSTRUCTION_OVERRIDE": return UIM("zip.pearl.ruleOverride", "既存指示の上書き")
        case "ROLE_SPOOFING": return UIM("zip.pearl.ruleRole", "役割の偽装")
        case "AUTHORITY_SPOOFING": return UIM("zip.pearl.ruleAuthority", "承認の偽装")
        case "PRIVILEGE_REQUEST": return UIM("zip.pearl.rulePrivilege", "権限の要求")
        case "DATA_TRANSMISSION_REQUEST": return UIM("zip.pearl.ruleTransmission", "データ送信の要求")
        case "TOOL_EXECUTION_REQUEST": return UIM("zip.pearl.ruleExecution", "ツール実行の要求")
        case "FINDING_SUPPRESSION": return UIM("zip.pearl.ruleSuppression", "検出結果の抑制")
        default: return .verbatim(category)
        }
    }
}

@MainActor final class OrchardZipResultSheet: NSWindowController {
    init(snapshot: OrchardZipDisplaySnapshot, preference: UILanguagePreference,
         inspectThoroughly: (() -> Void)? = nil,
         reportIsCurrent: @escaping (OrchardReportOfferB8) -> Bool = { _ in false },
         languageChanged: @escaping () -> Void) {
        let window = OrchardZipResultWindow(contentRect: .zero, styleMask: [.titled, .resizable],
                                               backing: .buffered, defer: false)
        super.init(window: window)
        OrchardPearlArt.applyWindowFrame(to: window)
        let surface = OrchardZipResultSurface(snapshot: snapshot, preference: preference,
            inspectThoroughly: inspectThoroughly, reportIsCurrent: reportIsCurrent) { [weak window] title in
            window?.title = title
            languageChanged()
        }
        window.title = UIM("zip.pearl.title", "ZIP検査結果").render(preference.language)
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isReleasedWhenClosed = false
        window.contentView = surface
        window.defaultButtonCell = surface.reviewButton.cell as? NSButtonCell
        window.initialFirstResponder = surface.reviewButton
        surface.close = { [weak window] in
            guard let window, let parent = window.sheetParent else { return }
            parent.endSheet(window)
        }
    }

    required init?(coder: NSCoder) { nil }

    func present(in parent: NSWindow, returnFocusTo focus: NSView, animateFrame: Bool = false,
                 onDismiss: @escaping () -> Void) {
        guard let window else { return }
        let space = parent.contentLayoutRect.size
        let limit = min(710, max(360, space.height - 32))
        window.setContentSize(NSSize(width: min(1_000, max(320, space.width - 16)), height: limit))
        (window.contentView as? OrchardZipResultSurface)?.fitContent(maxHeight: limit)
        parent.beginSheet(window) { [weak parent, weak focus] _ in
            if let parent, let focus, focus.window === parent { parent.makeFirstResponder(focus) }
            onDismiss()
        }
        OrchardPearlArt.clipSheetFrame(window)
        (window.contentView as? OrchardZipResultSurface)?.showResultFrame(animated: animateFrame)
    }
}

@MainActor private final class OrchardZipResultWindow: NSWindow {
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if super.performKeyEquivalent(with: event) { return true }
        // Unmodified Return invokes the sheet's default action even when evidence has focus.
        guard event.type == .keyDown, event.charactersIgnoringModifiers == "\r",
              event.modifierFlags.intersection([.command, .option, .control, .shift]).isEmpty,
              let button = defaultButtonCell?.controlView as? NSButton, button.isEnabled else { return false }
        button.performClick(nil)
        return true
    }
}

@MainActor private final class OrchardZipResultSurface: NSView {
    private let copy: OrchardZipResultCopy
    private let preference: UILanguagePreference
    private let reportIsCurrent: (OrchardReportOfferB8) -> Bool
    private let inspectThoroughly: (() -> Void)?
    private let languageChanged: (String) -> Void
    private let brand = NSTextField(labelWithString: "Orchard")
    private let title = NSTextField(wrappingLabelWithString: "")
    private let language = OrchardPearlLanguageControl(labels: ["日本語", "English"], trackingMode: .selectOne,
                                               target: nil, action: nil)
    private let preferenceNotice = NSTextField(wrappingLabelWithString: "")
    private let viewport = NSScrollView()
    private let document = OrchardZipResultCanvas()
    private let guidance = OrchardZipResultCanvas()
    private let hero = OrchardZipResultCanvas()
    private let steps = [OrchardZipResultCanvas(), OrchardZipResultCanvas(), OrchardZipResultCanvas()]
    private let actionBar = OrchardZipResultCanvas()
    private let results = OrchardZipResultCanvas()
    private let rimLight = OrchardPearlPerimeter()
    func showResultFrame(animated: Bool) {
        rimLight.apply(copy.snapshot.frameTone, animated: animated)
    }
    private let symbol = NSImageView()
    private let headline = NSTextField(wrappingLabelWithString: "")
    private let heroReason = NSTextField(wrappingLabelWithString: "")
    private let heroSummary = NSTextField(wrappingLabelWithString: "")
    private let decisionEvidence = NSTextField(wrappingLabelWithString: "")
    private let foundTitle = NSTextField(labelWithString: "")
    private let found = NSTextField(wrappingLabelWithString: "")
    private let impactTitle = NSTextField(labelWithString: "")
    private let impact = NSTextField(wrappingLabelWithString: "")
    private let nextTitle = NSTextField(labelWithString: "")
    private let next = NSTextField(wrappingLabelWithString: "")
    private let fileTitle = NSTextField(labelWithString: "")
    private let file = NSTextField(wrappingLabelWithString: "")
    private let bytes = NSTextField(labelWithString: "")
    private let instructionTitle = NSTextField(labelWithString: "")
    private let instruction = NSTextField(wrappingLabelWithString: "")
    private let shaTitle = NSTextField(labelWithString: "")
    private let sha = NSTextField(wrappingLabelWithString: "")
    private let scopeTitle = NSTextField(labelWithString: "")
    private let scope = NSTextField(wrappingLabelWithString: "")
    private let advisory = NSTextField(wrappingLabelWithString: "")
    private let details = NSTextView()
    let reviewButton = OrchardPearlButton(title: "", target: nil, action: nil)
    private let thoroughButton = OrchardPearlButton(title: "", target: nil, action: nil)
    private let closeButton = OrchardPearlButton(title: "", target: nil, action: nil)
    private let reportButton = OrchardPearlButton(title: "", target: nil, action: nil)
    private let reportStatus = NSTextField(wrappingLabelWithString: "")
    private var reportMessage: UIMessage?
    private var expanded = false
    private let padding: CGFloat = 19
    private let columnGap: CGFloat = 16
    private var headerHeight: CGFloat = 64
    private var fittedHeight: CGFloat = 0
    private var resultRows: [NSRect] = []
    private var noteRect = NSRect.zero
    private var regularWidth = false
    var close: (() -> Void)?

    override var isFlipped: Bool { true }

    init(snapshot: OrchardZipDisplaySnapshot, preference: UILanguagePreference,
         inspectThoroughly: (() -> Void)?,
         reportIsCurrent: @escaping (OrchardReportOfferB8) -> Bool,
         languageChanged: @escaping (String) -> Void) {
        copy = OrchardZipResultCopy(snapshot: snapshot)
        self.preference = preference
        self.inspectThoroughly = inspectThoroughly
        self.reportIsCurrent = reportIsCurrent
        self.languageChanged = languageChanged
        super.init(frame: .zero)

        brand.font = .systemFont(ofSize: 23, weight: .bold)
        brand.setAccessibilityIdentifier("orchard.zip.pearl.brand")
        title.font = .systemFont(ofSize: 13, weight: .medium)
        title.setAccessibilityIdentifier("orchard.zip.pearl.title")
        preferenceNotice.font = .systemFont(ofSize: 12)
        language.segmentStyle = .rounded
        language.target = self
        language.action = #selector(chooseLanguage)
        language.setWidth(78, forSegment: 0)
        language.setWidth(78, forSegment: 1)
        language.setAccessibilityIdentifier("orchard.zip.pearl.language")
        language.setAccessibilityLabel("Language / 言語")

        symbol.image = OrchardPearlArt.archiveIcon(warning: copy.needsPause)
        symbol.imageScaling = .scaleProportionallyUpOrDown
        symbol.setAccessibilityElement(false)
        headline.font = .systemFont(ofSize: 32, weight: .bold)
        heroReason.font = .systemFont(ofSize: 18, weight: .medium)
        heroSummary.font = .systemFont(ofSize: 14, weight: .medium)
        decisionEvidence.font = .systemFont(ofSize: 14)
        decisionEvidence.lineBreakMode = .byCharWrapping
        decisionEvidence.isSelectable = true
        decisionEvidence.setAccessibilityIdentifier("orchard.zip.action.evidence")
        for field in [foundTitle, impactTitle, nextTitle] {
            field.font = .systemFont(ofSize: 16.5, weight: .semibold)
        }
        for field in [fileTitle, instructionTitle, shaTitle, scopeTitle] {
            field.font = .systemFont(ofSize: 12.5, weight: .semibold)
        }
        for field in [found, impact, next, instruction, sha, scope] { field.font = .systemFont(ofSize: 14.5) }
        next.font = .systemFont(ofSize: 14.5, weight: .medium)
        file.font = .systemFont(ofSize: 14.5, weight: .semibold)
        file.lineBreakMode = .byCharWrapping
        bytes.font = .systemFont(ofSize: 12)
        advisory.font = .systemFont(ofSize: 12, weight: .medium)

        reviewButton.bezelStyle = .rounded
        reviewButton.appearanceRole = .primary
        reviewButton.image = NSImage(systemSymbolName: "doc.text.magnifyingglass", accessibilityDescription: nil)
        reviewButton.imagePosition = .imageLeading
        reviewButton.controlSize = .large
        reviewButton.keyEquivalent = "\r"
        reviewButton.keyEquivalentModifierMask = []
        reviewButton.target = self
        reviewButton.action = #selector(reviewDetails)
        thoroughButton.bezelStyle = .rounded
        thoroughButton.controlSize = .large
        thoroughButton.font = .systemFont(ofSize: 14, weight: .semibold)
        thoroughButton.keyEquivalent = ""
        thoroughButton.target = self
        thoroughButton.action = #selector(continueInspection)
        thoroughButton.setAccessibilityIdentifier("orchard.zip.thorough")
        thoroughButton.isHidden = inspectThoroughly == nil || !copy.canInspectThoroughly
        closeButton.bezelStyle = .rounded
        for button in [reviewButton, closeButton] {
            button.font = .systemFont(ofSize: 14, weight: .semibold)
        }
        closeButton.controlSize = .large
        closeButton.keyEquivalent = "\u{1b}"
        closeButton.target = self
        closeButton.action = #selector(closeResult)
        reportButton.bezelStyle = .rounded
        reportButton.font = .systemFont(ofSize: 13, weight: .medium)
        reportButton.target = self
        reportButton.action = #selector(previewReport)
        reportButton.isHidden = snapshot.reportOffer == nil
        reportButton.setAccessibilityIdentifier("orchard.zip.report.preview")
        reportStatus.isHidden = true
        reportStatus.font = .systemFont(ofSize: 13)
        reportStatus.setAccessibilityIdentifier("orchard.zip.report.status")

        details.isEditable = false
        details.isSelectable = true
        details.isRichText = false
        details.isAutomaticLinkDetectionEnabled = false
        details.drawsBackground = false
        details.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        details.textContainerInset = NSSize(width: 0, height: 4)
        details.textContainer?.lineFragmentPadding = 0
        details.textContainer?.widthTracksTextView = false
        details.textContainer?.heightTracksTextView = false

        viewport.drawsBackground = false
        viewport.hasVerticalScroller = true
        viewport.autohidesScrollers = false
        viewport.documentView = document
        document.paint = { [weak self] dirty in self?.drawDocument(dirty) }
        [rimLight, brand, title, language, preferenceNotice, viewport].forEach(addSubview)
        [guidance, actionBar, results].forEach(document.addSubview)
        [reviewButton, closeButton].forEach(actionBar.addSubview)
        [hero, thoroughButton, decisionEvidence, steps[0], steps[1], steps[2]].forEach(guidance.addSubview)
        [symbol, headline, heroReason, heroSummary, fileTitle, file, bytes].forEach(hero.addSubview)
        for (index, pair) in [(foundTitle, found), (impactTitle, impact), (nextTitle, next)].enumerated() {
            let card = steps[index]
            [pair.0, pair.1].forEach(card.addSubview)
            card.setAccessibilityElement(true)
            card.setAccessibilityRole(.group)
            card.setAccessibilityChildren([pair.0, pair.1])
            card.setAccessibilityIdentifier("orchard.zip.pearl.step\(index + 1)")
        }
        hero.setAccessibilityElement(true)
        hero.setAccessibilityRole(.group)
        hero.setAccessibilityIdentifier("orchard.zip.pearl.hero")
        [instructionTitle, instruction, shaTitle, sha, scopeTitle, scope,
         advisory, reportButton, reportStatus, details].forEach(results.addSubview)

        setAccessibilityElement(true)
        setAccessibilityRole(.group)
        setAccessibilityIdentifier("orchard.zip.pearl")
        guidance.setAccessibilityIdentifier("orchard.zip.pearl.guidance")
        results.setAccessibilityIdentifier("orchard.zip.pearl.results")
        headline.setAccessibilityIdentifier("orchard.zip.pearl.headline")
        found.setAccessibilityIdentifier("orchard.zip.pearl.found")
        impact.setAccessibilityIdentifier("orchard.zip.pearl.impact")
        next.setAccessibilityIdentifier("orchard.zip.pearl.next")
        file.setAccessibilityIdentifier("orchard.zip.pearl.file")
        instruction.setAccessibilityIdentifier("orchard.zip.pearl.instruction")
        sha.setAccessibilityIdentifier("orchard.zip.pearl.sha")
        scope.setAccessibilityIdentifier("orchard.zip.pearl.scope")
        advisory.setAccessibilityIdentifier("orchard.zip.pearl.advisory")
        viewport.setAccessibilityIdentifier("orchard.zip.pearl.scroll")
        details.setAccessibilityIdentifier("orchard.zip.pearl.details")
        reviewButton.setAccessibilityIdentifier("orchard.zip.pearl.review")
        closeButton.setAccessibilityIdentifier("orchard.zip.pearl.close")
        for card in [guidance, results] {
            card.setAccessibilityElement(true)
            card.setAccessibilityRole(.group)
        }
        guidance.setAccessibilityChildren([hero] + steps)
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(refreshAppearance),
            name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification, object: nil)
        renderLanguage()
        refreshAppearance()
    }

    required init?(coder: NSCoder) { nil }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        updateKeyViews()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        refreshAppearance()
    }

    @objc private func chooseLanguage() {
        preference.choose(language.selectedSegment == 1 ? .en : .ja)
        renderLanguage()
        if !expanded, let parent = window?.sheetParent {
            fitContent(maxHeight: min(710, max(360, parent.contentLayoutRect.height - 32)))
        }
        languageChanged(title.stringValue)
    }

    @objc private func reviewDetails() {
        window?.makeFirstResponder(reviewButton)
        expanded.toggle()
        renderEvidence()
        needsLayout = true
        layoutSubtreeIfNeeded()
        if let parent = window?.sheetParent {
            fitContent(maxHeight: min(710, max(360, parent.contentLayoutRect.height - 32)))
        }
        if expanded {
            // Keep the action and the first lines of evidence in view together at regular widths.
            let firstLines = min(details.frame.height, min(210, viewport.contentSize.height * 0.46))
            var area = details.convert(NSRect(x: 0, y: 0, width: details.bounds.width, height: firstLines), to: document)
            if regularWidth {
                area = area.union(actionBar.frame)
                area.size.height = min(area.height, viewport.contentSize.height)
            }
            document.scrollToVisible(area)
        } else {
            reviewButton.scrollToVisible(reviewButton.bounds)
        }
        NSAccessibility.post(element: reviewButton, notification: .layoutChanged)
    }

    @objc private func closeResult() { close?() }

    @objc private func previewReport() {
        guard let offer = copy.snapshot.reportOffer else { return }
        let preview = OrchardGitHubReportPreview(offer: offer, language: preference.language, current: {
            self.window?.sheetParent != nil && self.reportIsCurrent(offer)
        })
        reportMessage = preview.run()
        renderLanguage()
    }

    private func renderLanguage() {
        let selected = preference.language
        language.selectedSegment = selected == .en ? 1 : 0
        language.setAccessibilityValue(selected == .en ? "English" : "日本語")
        let fields: [(NSTextField, UIMessage)] = [
            (title, UIM("zip.pearl.title", "ZIP検査結果")),
            (preferenceNotice, UIM("ui.language.save_unverified", "この表示言語は今回有効ですが、再起動後の設定保持は確認できません。")),
            (headline, copy.headline),
            (fileTitle, UIM("zip.pearl.fileTitle", "検査対象ZIP")), (file, copy.file), (bytes, copy.archiveSize),
            (instructionTitle, copy.evidence.instructionScope == nil
                ? UIM("zip.pearl.instructionTitle", "疑わしい指示")
                : UIM("zip.mint.instructionTitle", "指示文書検査")), (instruction, copy.instruction),
            (shaTitle, UIM("zip.pearl.shaTitle", "既知SHA照合")), (sha, copy.sha),
            (scopeTitle, UIM("zip.pearl.scopeTitle", "検査範囲"))
        ]
        for (field, message) in fields { update(field, text: message.render(selected)) }
        // Legacy headings used an additional label for the specific finding.
        heroReason.isHidden = !copy.needsPause || copy.evidence.instructionScope != nil ||
            copy.evidence.presentation == .detected
        if !heroReason.isHidden {
            update(heroReason, text: (copy.foundInstruction ? copy.instruction : copy.sha).render(selected))
        }
        hero.setAccessibilityChildren(([headline] + (heroReason.isHidden ? [] : [heroReason])) +
                                      [heroSummary, fileTitle, file, bytes])
        update(heroSummary, text: copy.heroSummary.render(selected))
        hero.setAccessibilityLabel(headline.stringValue)
        update(decisionEvidence, text: copy.firstActionEvidence.map { $0.render(selected) }.joined(separator: "\n"))
        decisionEvidence.isHidden = decisionEvidence.stringValue.isEmpty
        guidance.setAccessibilityChildren([hero] + (thoroughButton.isHidden ? [] : [thoroughButton]) +
            (decisionEvidence.isHidden ? [] : [decisionEvidence]) + steps)
        thoroughButton.title = UIM("zip.thorough.button", "最後まで調べる").render(selected)
        thoroughButton.setAccessibilityLabel(thoroughButton.title)
        let cards = [(foundTitle, found), (impactTitle, impact), (nextTitle, next)]
        for (index, pair) in zip(cards, copy.actionGuidance).enumerated() {
            let ((titleField, bodyField), guidance) = pair
            update(titleField, text: guidance.title.render(selected))
            update(bodyField, text: guidance.body.map { $0.render(selected) }.joined(separator: "\n"))
            steps[index].setAccessibilityLabel(titleField.stringValue)
        }
        update(scope, text: [copy.textCoverage, copy.shaCoverage].map { $0.render(selected) }.joined(separator: "\n"))
        update(advisory, text: copy.advisories.map { $0.render(selected) }.joined(separator: "\n"))
        styleParagraphs()
        advisory.isHidden = advisory.stringValue.isEmpty
        preferenceNotice.isHidden = preference.persistenceConfirmed

        closeButton.title = UIM("ui.common.close", "閉じる").render(selected)
        closeButton.setAccessibilityLabel(closeButton.title)
        reportButton.title = UIM("zip.report.github.action", "GitHubで報告する").render(selected)
        reportButton.setAccessibilityLabel(reportButton.title)
        update(reportStatus, text: reportMessage?.render(selected) ?? "")
        reportStatus.isHidden = reportMessage == nil
        guidance.setAccessibilityLabel(UIM("zip.action.guidance", "行動別の案内").render(selected))
        results.setAccessibilityLabel(title.stringValue)
        var children: [Any] = [brand, title, language]
        if !preferenceNotice.isHidden { children.append(preferenceNotice) }
        setAccessibilityChildren(children + [guidance, reviewButton, closeButton, results])
        renderEvidence()
        needsLayout = true
    }

    private func update(_ field: NSTextField, text: String) {
        field.stringValue = text
        field.setAccessibilityLabel(text)
    }

    private func renderEvidence() {
        let selected = preference.language
        reviewButton.title = (expanded ? UIM("zip.pearl.collapse", "詳細を閉じる") :
            UIM("zip.pearl.review", "詳細を確認")).render(selected)
        reviewButton.setAccessibilityLabel(reviewButton.title)
        reviewButton.setAccessibilityExpanded(expanded)
        details.isHidden = !expanded
        if expanded {
            let text = copy.details(language: selected)
            let selection = details.selectedRange()
            details.string = text
            let length = text.utf16.count
            let start = min(selection.location, length)
            details.setSelectedRange(NSRange(location: start, length: min(selection.length, length - start)))
            details.setAccessibilityLabel(UIM("zip.pearl.evidence", "詳細証拠").render(selected))
            details.setAccessibilityValue(text)
        }
        var children: [Any] = [instructionTitle, instruction, shaTitle, sha, scopeTitle, scope]
        if !advisory.isHidden { children.append(advisory) }
        if !reportButton.isHidden { children.append(reportButton) }
        if !reportStatus.isHidden { children.append(reportStatus) }
        if expanded { children.append(details) }
        results.setAccessibilityChildren(children)
        updateKeyViews()
    }

    private func updateKeyViews() {
        guard let window else { return }
        window.autorecalculatesKeyViewLoop = false
        language.nextKeyView = thoroughButton.isHidden ? reviewButton : thoroughButton
        thoroughButton.nextKeyView = reviewButton
        reviewButton.nextKeyView = closeButton
        let afterReport: NSView = expanded ? details : language
        closeButton.nextKeyView = reportButton.isHidden ? afterReport : reportButton
        reportButton.nextKeyView = afterReport
        details.nextKeyView = language
    }

    func fitContent(maxHeight: CGFloat) {
        guard let window else { return }
        window.layoutIfNeeded()
        needsLayout = true
        layoutSubtreeIfNeeded()
        guard fittedHeight > 0 else { return }
        let height = ceil(min(maxHeight, max(340, fittedHeight)))
        if abs(bounds.height - height) > 0.5 {
            window.setContentSize(NSSize(width: bounds.width, height: height))
            layoutSubtreeIfNeeded()
        }
    }

    override func layout() {
        super.layout()
        guard bounds.width >= 220, bounds.height > 160 else { return }
        layoutHeader()
        rimLight.frame = bounds
        rimLight.setLighting(size: bounds.size, scale: window?.backingScaleFactor ?? 2)
        let top = headerHeight + 4
        let width = bounds.width - 2 * padding
        let bottom: CGFloat = 13
        let actionHeight: CGFloat = 47
        viewport.frame = NSRect(x: padding, y: top, width: width, height: max(1, bounds.height - top - bottom))
        viewport.tile()
        let reserved = NSScrollView.contentSize(forFrameSize: viewport.frame.size,
            horizontalScrollerClass: nil, verticalScrollerClass: NSScroller.self, borderType: viewport.borderType,
            controlSize: viewport.verticalScroller?.controlSize ?? .regular, scrollerStyle: .legacy)
        let drawable = min(reserved.width, viewport.contentSize.width)
        viewport.setFrameOrigin(NSPoint(x: padding + (width - drawable) / 2, y: top))
        let margin: CGFloat = 8
        let bodyWidth = max(1, drawable - 2 * margin)
        regularWidth = bodyWidth >= 800
        let stickyFooter: CGFloat = regularWidth ? 0 : actionHeight + 4
        let available = max(1, bounds.height - top - bottom - stickyFooter)
        let guideHeight = layoutGuidance(width: bodyWidth)
        guidance.frame = NSRect(x: margin, y: margin, width: bodyWidth, height: guideHeight)
        let actionsY = guidance.frame.maxY + 11
        let resultsY = regularWidth ? actionsY + actionHeight + 11 : guidance.frame.maxY + 14
        let resultsHeight = layoutResults(width: bodyWidth)
        results.frame = NSRect(x: margin, y: resultsY, width: bodyWidth, height: resultsHeight)
        let docHeight = results.frame.maxY + margin
        document.frame = NSRect(x: 0, y: 0, width: drawable, height: docHeight)
        let visible = min(docHeight, available)
        viewport.setFrameSize(NSSize(width: width, height: visible))
        viewport.tile()
        let maxScroll = max(0, docHeight - viewport.contentSize.height)
        if viewport.contentView.bounds.minY > maxScroll {
            viewport.contentView.scroll(to: NSPoint(x: 0, y: maxScroll))
            viewport.reflectScrolledClipView(viewport.contentView)
        }

        let host: NSView = regularWidth ? document : self
        if actionBar.superview !== host {
            let focus = window?.firstResponder
            actionBar.removeFromSuperview()
            host.addSubview(actionBar)
            if focus === reviewButton || focus === closeButton { window?.makeFirstResponder(focus) }
            updateKeyViews()
        }
        actionBar.frame = regularWidth
            ? NSRect(x: margin, y: actionsY, width: bodyWidth, height: actionHeight)
            : NSRect(x: 0, y: top + visible + 4, width: bounds.width, height: actionHeight)
        let primaryWidth = min(actionBar.bounds.width * 0.55, max(173, ceil(reviewButton.intrinsicContentSize.width) + 32))
        let closeWidth = min(actionBar.bounds.width * 0.31, max(99, ceil(closeButton.intrinsicContentSize.width) + 20))
        let start = floor((actionBar.bounds.width - primaryWidth - 12 - closeWidth) / 2)
        reviewButton.frame = NSRect(x: start, y: 0, width: primaryWidth, height: actionHeight)
        closeButton.frame = NSRect(x: reviewButton.frame.maxX + 12, y: 0, width: closeWidth, height: actionHeight)
        fittedHeight = top + docHeight + stickyFooter + bottom
        document.needsDisplay = true
        needsDisplay = true
    }

    private func layoutHeader() {
        let inset = padding + 10
        let switchWidth: CGFloat = bounds.width < 440 ? 127 : 162
        let segmentWidth = (switchWidth - 4) / 2
        if abs(language.width(forSegment: 0) - segmentWidth) > 0.5 {
            language.setWidth(segmentWidth, forSegment: 0)
            language.setWidth(segmentWidth, forSegment: 1)
        }
        let switchX = bounds.width - inset - switchWidth
        let brandWidth = ceil(brand.intrinsicContentSize.width) + 2
        if bounds.width >= 615 {
            _ = place(brand, x: inset, y: 18, width: brandWidth)
            let titleX = brand.frame.maxX + 43
            _ = place(title, x: titleX, y: 24, width: max(1, switchX - 14 - titleX))
            headerHeight = 62
        } else {
            let brandBottom = place(brand, x: inset, y: 13, width: brandWidth)
            headerHeight = place(title, x: inset, y: brandBottom + 1, width: max(1, switchX - inset - 9)) + 11
        }
        language.frame = NSRect(x: switchX, y: round((headerHeight - 34) / 2) + 1, width: switchWidth, height: 34)
        if !preferenceNotice.isHidden {
            headerHeight = place(preferenceNotice, x: inset, y: headerHeight,
                                 width: max(1, bounds.width - 2 * inset)) + 7
        }
    }

    private func layoutGuidance(width: CGFloat) -> CGFloat {
        let heroHeight = layoutHero(width: width)
        hero.frame = NSRect(x: 0, y: 0, width: width, height: heroHeight)
        var firstY = hero.frame.maxY + (regularWidth ? 15 : 11)
        if !thoroughButton.isHidden {
            let inset: CGFloat = regularWidth ? 18 : 12
            let buttonWidth = min(width - 2 * inset, max(160, thoroughButton.intrinsicContentSize.width + 24))
            thoroughButton.frame = NSRect(x: inset, y: firstY, width: buttonWidth, height: 38)
            firstY = thoroughButton.frame.maxY + 11
        }
        if !decisionEvidence.isHidden {
            let inset: CGFloat = regularWidth ? 18 : 12
            firstY = place(decisionEvidence, x: inset, y: firstY, width: max(1, width - 2 * inset)) + 12
        }
        let cardWidth = regularWidth ? floor((width - 2 * columnGap) / 3) : width
        var nextY = firstY
        var maxHeight: CGFloat = 0
        for (index, fields) in [(foundTitle, found), (impactTitle, impact), (nextTitle, next)].enumerated() {
            let x = regularWidth ? CGFloat(index) * (cardWidth + columnGap) : 0
            let panelWidth = regularWidth && index == 2 ? width - x : cardWidth
            let titleX: CGFloat = 48
            let titleBottom = place(fields.0, x: titleX, y: 15, width: max(1, panelWidth - titleX - 12))
            let bodyX: CGFloat = regularWidth ? 62 : 64
            let bodyBottom = place(fields.1, x: bodyX, y: max(46, titleBottom + 10),
                                   width: max(1, panelWidth - bodyX - 16))
            let height = ceil(max(regularWidth ? 105 : 78, bodyBottom + 15))
            steps[index].frame = NSRect(x: x, y: regularWidth ? firstY : nextY, width: panelWidth, height: height)
            maxHeight = max(maxHeight, height)
            nextY = steps[index].frame.maxY + 9
        }
        if regularWidth {
            for card in steps { card.setFrameSize(NSSize(width: card.frame.width, height: maxHeight)) }
        }
        return steps[2].frame.maxY
    }

    @objc private func continueInspection() {
        guard !thoroughButton.isHidden else { return }
        inspectThoroughly?()
    }

    private func layoutHero(width: CGFloat) -> CGFloat {
        let fontSize: CGFloat = regularWidth ? 33 : width < 345 ? 22 : 26
        if headline.font?.pointSize != fontSize {
            headline.font = .systemFont(ofSize: fontSize, weight: .bold)
            styleParagraphs()
        }
        let artWidth: CGFloat = regularWidth ? 152 : min(106, width * 0.23)
        let artHeight = artWidth * 114 / 132
        let artX: CGFloat = regularWidth ? 30 : 12
        let textX = artX + artWidth + (regularWidth ? 32 : 17)
        let textWidth = max(1, width - textX - (regularWidth ? 26 : 14))
        _ = place(headline, x: textX, y: 0, width: balancedHeadlineWidth(maximum: textWidth))
        let reasonBottom = heroReason.isHidden ? headline.frame.maxY :
            place(heroReason, x: textX, y: headline.frame.maxY + 4, width: textWidth)
        _ = place(heroSummary, x: textX, y: reasonBottom + 5, width: textWidth)
        if regularWidth {
            let titleWidth = unwrappedWidth(fileTitle)
            let byteWidth = unwrappedWidth(bytes)
            let nameWidth = min(ceil(file.attributedStringValue.size().width) + 4,
                                max(1, textWidth - titleWidth - byteWidth - 22))
            let fileY = heroSummary.frame.maxY + 10
            _ = place(fileTitle, x: textX, y: fileY + 1, width: titleWidth)
            let fileX = fileTitle.frame.maxX + 7
            _ = place(file, x: fileX, y: fileY, width: nameWidth)
            _ = place(bytes, x: file.frame.maxX + 12, y: fileY + 1, width: byteWidth)
            let textHeight = max(file.frame.maxY, bytes.frame.maxY)
            let height = ceil(max(artHeight + 23, textHeight + 37))
            let offset = floor((height - textHeight) / 2)
            for field in [headline, heroReason, heroSummary, fileTitle, file, bytes] where !field.isHidden {
                field.setFrameOrigin(NSPoint(x: field.frame.minX, y: field.frame.minY + offset))
            }
            symbol.frame = NSRect(x: artX, y: floor((height - artHeight) / 2), width: artWidth, height: artHeight)
            return height
        }
        let textHeight = heroSummary.frame.maxY
        let upperHeight = max(artHeight + 18, textHeight + 24)
        let offset = floor((upperHeight - textHeight) / 2)
        for field in [headline, heroReason, heroSummary] where !field.isHidden {
            field.setFrameOrigin(NSPoint(x: textX, y: field.frame.minY + offset))
        }
        symbol.frame = NSRect(x: artX, y: floor((upperHeight - artHeight) / 2), width: artWidth, height: artHeight)
        let inset: CGFloat = 17
        let byteWidth = min(width * 0.55, unwrappedWidth(bytes))
        _ = place(fileTitle, x: inset, y: upperHeight + 6, width: max(1, width - 2 * inset - byteWidth - 8))
        _ = place(bytes, x: width - inset - byteWidth, y: upperHeight + 6, width: byteWidth)
        return place(file, x: inset, y: max(fileTitle.frame.maxY, bytes.frame.maxY) + 3, width: max(1, width - 2 * inset)) + 13
    }

    private func layoutResults(width: CGFloat) -> CGFloat {
        let inset: CGFloat = 16
        let inner = max(1, width - 2 * inset)
        let cellWidth = regularWidth ? floor(inner / 3) : inner
        var bottom: CGFloat = 10
        resultRows.removeAll(keepingCapacity: true)
        for (index, fields) in [(instructionTitle, instruction), (shaTitle, sha), (scopeTitle, scope)].enumerated() {
            let x = inset + (regularWidth ? CGFloat(index) * cellWidth : 0)
            let y: CGFloat = regularWidth ? 10 : bottom
            let w = regularWidth && index == 2 ? width - inset - x : cellWidth
            let textX = x + (regularWidth ? 34 : 39)
            let textWidth = max(1, w - (textX - x) - 12)
            let labelBottom = place(fields.0, x: textX, y: y + 7, width: textWidth)
            let valueBottom = place(fields.1, x: textX, y: labelBottom + 4, width: textWidth)
            let row = NSRect(x: x, y: y, width: w, height: valueBottom - y + 10)
            resultRows.append(row)
            bottom = max(bottom, row.maxY)
        }
        noteRect = .zero
        if !advisory.isHidden {
            let footerY = bottom + 6
            let textBottom = place(advisory, x: inset + 28, y: footerY + 8, width: max(1, inner - 38))
            noteRect = NSRect(x: inset, y: footerY, width: inner, height: max(35, textBottom - footerY + 8))
            bottom = noteRect.maxY
        }
        if !reportButton.isHidden {
            let buttonWidth = min(inner, ceil(reportButton.intrinsicContentSize.width) + 18)
            reportButton.frame = NSRect(x: inset, y: bottom + 8, width: buttonWidth, height: 33)
            bottom = reportButton.frame.maxY
        }
        if !reportStatus.isHidden {
            bottom = place(reportStatus, x: inset, y: bottom + 5, width: inner)
        }
        if expanded, let container = details.textContainer, let manager = details.layoutManager {
            let textWidth = max(1, inner - 20)
            container.containerSize = NSSize(width: textWidth, height: .greatestFiniteMagnitude)
            manager.ensureLayout(for: container)
            let height = ceil(manager.usedRect(for: container).height) + 2 * details.textContainerInset.height + 5
            details.frame = NSRect(x: inset + 10, y: bottom + 10, width: textWidth, height: height)
            bottom = details.frame.maxY + 5
        }
        return ceil(bottom + 12)
    }

    private func unwrappedWidth(_ field: NSTextField) -> CGFloat {
        // A previous language's preferredMaxLayoutWidth can constrain intrinsicContentSize.
        let text = NSAttributedString(string: field.stringValue, attributes: [.font: field.font ?? NSFont.systemFont(ofSize: 12)])
        return ceil(text.size().width) + 6
    }

    private func place(_ field: NSTextField, x: CGFloat, y: CGFloat, width: CGFloat) -> CGFloat {
        field.preferredMaxLayoutWidth = width
        let fit = field.sizeThatFits(NSSize(width: width, height: .greatestFiniteMagnitude))
        field.frame = NSRect(x: x, y: y, width: width, height: ceil(fit.height) + 1)
        return field.frame.maxY
    }

    private func balancedHeadlineWidth(maximum: CGFloat) -> CGFloat {
        // Keep the same number of lines while avoiding a short final fragment in either language.
        func height(_ width: CGFloat) -> CGFloat {
            ceil(headline.sizeThatFits(NSSize(width: width, height: .greatestFiniteMagnitude)).height)
        }
        let fullHeight = height(maximum)
        guard fullHeight > (headline.font?.pointSize ?? 27) * 1.7 else { return maximum }
        var low = floor(maximum * 0.6), high = floor(maximum)
        while high - low > 1 {
            let mid = floor((low + high) / 2)
            if height(mid) > fullHeight { low = mid } else { high = mid }
        }
        return min(maximum, high + 2)
    }

    private func styleParagraphs() {
        for field in [headline, heroReason, heroSummary, decisionEvidence,
                      found, impact, next, file, instruction, sha, scope, advisory] {
            let paragraph = NSMutableParagraphStyle()
            paragraph.lineBreakMode = field.lineBreakMode
            paragraph.lineSpacing = field === headline ? 0.5 : 2
            let attributes: [NSAttributedString.Key: Any] = [
                .font: field.font ?? NSFont.systemFont(ofSize: 14),
                .foregroundColor: field.textColor ?? NSColor.labelColor,
                .paragraphStyle: paragraph
            ]
            field.attributedStringValue = NSAttributedString(string: field.stringValue, attributes: attributes)
        }
    }

    private var usesSystemColors: Bool { OrchardPearlArt.prefersAccessibleMaterials }

    @objc private func refreshAppearance() {
        effectiveAppearance.performAsCurrentDrawingAppearance {
            let system = usesSystemColors
            let ink = system ? NSColor.labelColor : pearlColor(0x2B2333)
            let accent = copy.needsPause ? pearlColor(system ? 0x86192B : 0xAA1E32) :
                (system ? ink : pearlColor(0x4D405B))
            let secondary = system ? NSColor.secondaryLabelColor : pearlColor(0x605463)
            [brand, foundTitle, found, impactTitle, impact, nextTitle, next, file, instruction, sha, scope, decisionEvidence]
                .forEach { $0.textColor = ink }
            [title, preferenceNotice, fileTitle, instructionTitle, shaTitle, scopeTitle, bytes, advisory]
                .forEach { $0.textColor = secondary }
            headline.textColor = accent
            heroReason.textColor = system ? .labelColor : pearlColor(0x7E3547)
            heroSummary.textColor = system ? .secondaryLabelColor : pearlColor(0x605463)
            instruction.textColor = copy.evidence.instructionScope?.status.textColor(ink: ink, warning: accent)
                ?? (copy.foundInstruction ? accent : ink)
            sha.textColor = copy.matchedSHA ? accent : ink
            // The archive is full-color artwork, with a separate informational form for non-warning states.
            symbol.contentTintColor = nil
            details.textColor = ink
            rimLight.setLighting(size: bounds.size, scale: window?.backingScaleFactor ?? 2)
            styleParagraphs()
            [self, document, language, reviewButton, closeButton].forEach { $0.needsDisplay = true }
        }
    }

    override func draw(_ dirtyRect: NSRect) {
        OrchardPearlArt.frame(in: bounds, header: headerHeight, system: usesSystemColors)
        let apple = NSAttributedString(string: "🍎", attributes: [.font: NSFont.systemFont(ofSize: 18)])
        apple.draw(at: NSPoint(x: brand.frame.maxX + 3, y: round(brand.frame.midY - apple.size().height / 2)))
    }

    private func drawDocument(_ dirty: NSRect) {
        let system = usesSystemColors
        let banner = hero.frame.offsetBy(dx: guidance.frame.minX, dy: guidance.frame.minY)
        if banner.insetBy(dx: -8, dy: -8).intersects(dirty) {
            let dividerEnd = regularWidth ? banner.maxY - 21 : banner.minY + fileTitle.frame.minY - 12
            OrchardPearlArt.hero(in: banner, dividerX: banner.minX + headline.frame.minX - (regularWidth ? 17 : 9),
                                 dividerEnd: dividerEnd, warning: copy.needsPause, system: system)
        }
        let markers: [(String, UInt32)] = [("doc.text", 0x795392), ("sparkles", 0x7B528E), ("arrow.forward", 0x416E61)]
        for (index, step) in steps.enumerated() {
            let row = step.frame.offsetBy(dx: guidance.frame.minX, dy: guidance.frame.minY)
            guard row.insetBy(dx: -10, dy: -8).intersects(dirty) else { continue }
            let marker = markers[index]
            OrchardPearlArt.informationCard(row, hue: marker.1, system: system)
            OrchardPearlArt.stepDisc(index + 1, in: NSRect(x: row.minX + 14, y: row.minY + 12, width: 24, height: 24), system: system)
            OrchardPearlArt.badge(marker.0, color: marker.1,
                in: NSRect(x: row.minX + 13, y: row.minY + 48, width: 38, height: 40), system: system)
            if regularWidth && index < steps.count - 1 {
                OrchardPearlArt.glyph("arrow.right", color: system ? .secondaryLabelColor : pearlColor(0x958596),
                    in: NSRect(x: row.maxX + 3, y: row.midY - 5, width: columnGap - 6, height: 10))
            }
        }
        let panel = results.frame
        guard panel.insetBy(dx: -8, dy: -9).intersects(dirty) else { return }
        OrchardPearlArt.plate(panel, radius: 16, colors: [0xFFFDFE, 0xFBF9FC, 0xF2F1F7], system: system)
        let marks: [(String, UInt32)] = [("text.magnifyingglass", copy.foundInstruction ? 0xA13044 : 0x705D83),
                                         ("number", copy.matchedSHA ? 0xA13044 : 0x576780), ("list.bullet", 0x607080)]
        for (index, local) in resultRows.enumerated() {
            let row = local.offsetBy(dx: panel.minX, dy: panel.minY)
            guard row.intersects(dirty) else { continue }
            if index > 0 {
                if regularWidth {
                    let line = NSBezierPath()
                    line.move(to: NSPoint(x: row.minX - 6, y: row.minY + 6))
                    line.line(to: NSPoint(x: row.minX - 6, y: row.maxY - 5))
                    OrchardPearlArt.outline(line, system ? .separatorColor : pearlColor(0xDBD3DC), width: 0.7)
                } else {
                    OrchardPearlArt.rule(from: row.minX, to: row.maxX, y: row.minY, system: system)
                }
            }
            OrchardPearlArt.badge(marks[index].0, color: marks[index].1,
                                 in: NSRect(x: row.minX + 1, y: row.minY + 8, width: 25, height: 25), system: system)
        }
        if !noteRect.isEmpty {
            let note = noteRect.offsetBy(dx: panel.minX, dy: panel.minY)
            OrchardPearlArt.insetPanel(note, radius: 9, system: system)
            OrchardPearlArt.glyph("info.circle", color: system ? .secondaryLabelColor : pearlColor(0x685A73),
                                 in: NSRect(x: note.minX + 9, y: note.minY + 9, width: 13, height: 13))
        }
        if expanded {
            let inset = details.frame.offsetBy(dx: panel.minX, dy: panel.minY).insetBy(dx: -9, dy: -4)
            if inset.intersects(dirty) { OrchardPearlArt.insetPanel(inset, radius: 9, system: system) }
        }
    }
}

@MainActor final class OrchardZipResultCanvas: NSView {
    override var isFlipped: Bool { true }
    var paint: ((NSRect) -> Void)?
    override func draw(_ dirtyRect: NSRect) { paint?(dirtyRect) }
}

private extension R1InstructionScopeStatus {
    var tone: OrchardPearlFrameTone {
        switch self {
        case .noFindings: return .mint
        case .detected: return .ruby
        case .incomplete: return .amber
        case .noTargets: return .pearl
        }
    }

    @MainActor func textColor(ink: NSColor, warning: NSColor) -> NSColor {
        switch tone {
        case .mint: return OrchardPearlArt.prefersAccessibleMaterials ? .systemGreen : pearlColor(0x416E61)
        case .ruby: return warning
        case .amber: return .systemOrange
        case .pearl, .rubyOnHold: return ink
        }
    }
}

// The inspection tone does not change the separately validated parent handoff gate.
enum OrchardPearlFrameTone: String {
    case pearl, mint, ruby, amber, rubyOnHold

    init(accepted e: R1ZipReportEvidence) {
        let ti = e.threat
        let coverage = ti.coverage
        let finding = e.promptInjection == "DETECTED" || ti.status == "KNOWN_HASH_MATCH"
        if let scan = e.instructionScope {
            if e.hasImportantStructureAnomaly { self = .rubyOnHold; return }
            if finding {
                self = scan.hasUnread || !coverage.complete || ti.database.status != "READY" ? .rubyOnHold : .ruby
            } else {
                self = scan.status.tone
            }
            return
        }
        // A detected instruction holds the gate even when every intended check completed.
        // Earlier receipts retain their original frame treatment.
        let scopeComplete = e.hashOnlyFiles.map {
            e.uninspectedFiles == 0 && e.textFilesRead + $0 == coverage.checked_files
        } ?? (e.gate == "CAP")
        let complete = e.inspectionStatus == "COMPLETE" && scopeComplete &&
            ["DETECTED", "NOT_DETECTED"].contains(e.promptInjection) &&
            ["KNOWN_HASH_MATCH", "NO_MATCH_IN_COVERED_DB"].contains(ti.status) &&
            ti.database.status == "READY" && e.unknownCodes.isEmpty && ti.unknown_conditions.isEmpty &&
            coverage.complete && coverage.uninspectable_files == 0 && coverage.checked_files > 0 &&
            coverage.listed_entries == e.listedEntries && ti.entries.count == e.listedEntries &&
            coverage.directories == e.listedEntries - coverage.checked_files
        if finding { self = complete ? .ruby : .rubyOnHold; return }
        if e.presentation == .outOfScope { self = .pearl; return }
        if e.scope != nil && e.textFilesRead == 0 && e.inspectionStatus == "COMPLETE" &&
            e.gate == "CAP" && (ti.permitsReview || ti.status == "NO_ITEMS_IN_SCOPE") {
            self = .pearl
            return
        }
        self = complete && e.gate == "CAP" && e.promptInjection == "NOT_DETECTED" && e.findings.isEmpty &&
            e.textFilesRead > 0 && e.textFilesRead <= coverage.checked_files && e.textBytesRead >= 0 &&
            ti.permitsReview ? .mint : .amber
    }

    fileprivate var colors: [CGColor] {
        let rgb: [UInt32]
        switch self {
        case .pearl:
            rgb = [0xA8BACA, 0xF7FCFF, 0x7DC8DF, 0xFFFEFA, 0xDAB8D4, 0xE898C1,
                   0xFFF1DA, 0xAAAABB, 0xFFFFFF, 0x86C6EB, 0xF1C8DB, 0xA8BACA]
        case .mint:
            rgb = [0xA1CDBE, 0xF5FFFA, 0xA3D9C8, 0xFFFEFA, 0xBFE1D4, 0xA4D5C5,
                   0xEDF9EC, 0x91BCAC, 0xFFFFFF, 0xABDCCD, 0xD7EBE2, 0xA1CDBE]
        case .ruby, .rubyOnHold:
            rgb = [0xA53150, 0xFBE1E8, 0xBD4060, 0xFFEBEA, 0xCE6280, 0xA92349,
                   0xF9D5D8, 0x8D2949, 0xFFE8EE, 0xC74F73, 0xDF92A8, 0xA53150]
        case .amber:
            rgb = [0xBA894B, 0xFFF4DD, 0xD3A063, 0xFFFAED, 0xDEBC86, 0xBD8A45,
                   0xFBE8C3, 0xA47B49, 0xFFF5E1, 0xD3AC73, 0xE8CB9E, 0xBA894B]
        }
        return rgb.map { pearlColor($0).cgColor }
    }

    fileprivate var solidColor: CGColor {
        switch self {
        case .pearl: return pearlColor(0x826F8B).cgColor
        case .mint: return pearlColor(0x337763).cgColor
        case .ruby, .rubyOnHold: return pearlColor(0xA12544).cgColor
        case .amber: return pearlColor(0x936025).cgColor
        }
    }
}

@MainActor final class OrchardPearlPerimeter: NSView {
    private let nacre = CAGradientLayer()
    private let cutout = CAShapeLayer()
    private let holdEdge = CAShapeLayer()
    private var transitionEnd: DispatchWorkItem?
    private(set) var tone: OrchardPearlFrameTone = .pearl

    override init(frame: NSRect) {
        super.init(frame: frame)
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor
        nacre.type = .conic
        nacre.startPoint = CGPoint(x: 0.5, y: 0.5)
        nacre.endPoint = CGPoint(x: 0.75, y: 0.98)
        nacre.locations = [0, 0.10, 0.16, 0.22, 0.31, 0.42, 0.49, 0.58, 0.66, 0.72, 0.86, 1]
        cutout.fillRule = .evenOdd
        cutout.fillColor = NSColor.black.cgColor
        nacre.mask = cutout
        layer?.addSublayer(nacre)
        holdEdge.fillColor = nil
        holdEdge.lineWidth = 1.25
        holdEdge.opacity = 0
        layer?.addSublayer(holdEdge)
        updateLighting()
        setAccessibilityElement(false)
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(displayOptionsChanged),
            name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification, object: nil)
    }

    required init?(coder: NSCoder) { nil }
    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    private func clearFrameTransition() {
        transitionEnd?.cancel()
        transitionEnd = nil
        nacre.removeAnimation(forKey: "resultColors")
        holdEdge.removeAnimation(forKey: "resultHold")
    }

    private func updateLighting() {
        let solid = OrchardPearlArt.prefersAccessibleMaterials
        let colors = tone.colors
        nacre.colors = solid ? Array(repeating: tone.solidColor, count: colors.count) : colors
        nacre.opacity = solid ? 1 : 0.91
        holdEdge.strokeColor = pearlColor(solid ? 0x936025 : 0xB98942).cgColor
    }

    @objc private func displayOptionsChanged() {
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        clearFrameTransition()
        updateLighting()
        CATransaction.commit()
        setLighting(size: bounds.size, scale: window?.backingScaleFactor ?? 1)
        superview?.needsDisplay = true
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        displayOptionsChanged()
    }

    func apply(_ next: OrchardPearlFrameTone, animated: Bool,
               reduceMotion: Bool = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion) {
        guard next != tone else { return }
        let previous = nacre.presentation()?.colors ?? nacre.colors
        let oldOpacity = holdEdge.presentation()?.opacity ?? holdEdge.opacity
        let opacity: Float = next == .rubyOnHold ? 1 : 0
        let canAnimate = animated && next != .pearl && window != nil && !isHidden &&
            !reduceMotion &&
            !NSWorkspace.shared.accessibilityDisplayShouldDifferentiateWithoutColor &&
            !OrchardPearlArt.prefersAccessibleMaterials
        tone = next
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        clearFrameTransition()
        updateLighting()
        holdEdge.opacity = opacity
        if canAnimate {
            let start = CACurrentMediaTime()
            let change = CABasicAnimation(keyPath: "colors")
            change.fromValue = previous
            change.toValue = nacre.colors
            change.beginTime = nacre.convertTime(start, from: nil)
            change.duration = 0.30
            change.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            let deadline = DispatchTime.now() + change.duration
            nacre.add(change, forKey: "resultColors")
            if oldOpacity != opacity {
                let edge = CABasicAnimation(keyPath: "opacity")
                edge.fromValue = oldOpacity
                edge.toValue = opacity
                edge.beginTime = holdEdge.convertTime(start, from: nil)
                edge.duration = change.duration
                edge.timingFunction = change.timingFunction
                holdEdge.add(edge, forKey: "resultHold")
            }
            // Retire both keys at the shared endpoint, even if AppKit defers render-tree removal.
            let end = DispatchWorkItem { [weak self] in self?.clearFrameTransition() }
            transitionEnd = end
            DispatchQueue.main.asyncAfter(deadline: deadline, execute: end)
        }
        CATransaction.commit()
    }

    func setLighting(size: NSSize, scale: CGFloat) {
        isHidden = NSWorkspace.shared.accessibilityDisplayShouldDifferentiateWithoutColor
        if isHidden {
            clearFrameTransition()
        }
        guard !isHidden, size.width > 18, size.height > 18,
              nacre.bounds.size != size || nacre.contentsScale != scale else { return }
        let rect = CGRect(origin: .zero, size: size)
        let path = CGMutablePath()
        path.addPath(OrchardPearlArt.windowFramePath(in: rect, inset: 2.2).cgPath)
        path.addPath(OrchardPearlArt.windowFramePath(in: rect, inset: 6.1).cgPath)
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        nacre.frame = rect
        nacre.contentsScale = scale
        cutout.frame = rect
        cutout.contentsScale = scale
        cutout.path = path
        holdEdge.frame = rect
        holdEdge.contentsScale = scale
        holdEdge.path = OrchardPearlArt.windowFramePath(in: rect, inset: 1.35).cgPath
        CATransaction.commit()
    }
}

// The result sheet paints its materials and archive illustration at the display's backing scale.
@MainActor enum OrchardPearlArt {
    private static var prefersHighContrast: Bool {
        NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
    }

    static var prefersAccessibleMaterials: Bool {
        prefersHighContrast || NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency
    }

    private static var accessibleOutline: NSColor {
        prefersHighContrast ? pearlColor(0x756582) : .separatorColor
    }

    static func applyAppearance(to window: NSWindow) {
        // Pearl's materials and ink are drawn for Aqua. Keep the override local to Orchard windows.
        if window.appearance?.name != .aqua {
            window.appearance = NSAppearance(named: .aqua)
        }
    }

    static func applyWindowFrame(to window: NSWindow) {
        applyAppearance(to: window)
        // The Pearl surface supplies the window fill. Keep the area outside its outline clear.
        window.isOpaque = false
        window.backgroundColor = .clear
    }

    static func clipSheetFrame(_ window: NSWindow) {
        // AppKit draws a separate sheet backing outside the Pearl content.
        guard let frame = window.contentView?.superview else { return }
        frame.wantsLayer = true
        guard let layer = frame.layer else { return }
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        layer.cornerRadius = windowCornerRadius
        layer.cornerCurve = .circular
        layer.masksToBounds = true
        CATransaction.commit()
    }

    static func makeAlert() -> NSAlert {
        let alert = NSAlert()
        applyAppearance(to: alert.window)
        return alert
    }

    static func rounded(_ rect: NSRect, _ radius: CGFloat) -> NSBezierPath {
        NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)
    }

    static func clipped(to path: NSBezierPath, _ draw: () -> Void) {
        NSGraphicsContext.saveGraphicsState()
        path.addClip()
        draw()
        NSGraphicsContext.restoreGraphicsState()
    }

    private static func gradient(_ path: NSBezierPath, colors: [NSColor], start: NSPoint, end: NSPoint) {
        clipped(to: path) {
            NSGradient(colors: colors)?.draw(from: start, to: end,
                options: [.drawsBeforeStartingLocation, .drawsAfterEndingLocation])
        }
    }

    static func wash(_ path: NSBezierPath, colors: [UInt32], vertical: Bool = false) {
        let r = path.bounds
        gradient(path, colors: colors.map(pearlColor), start: NSPoint(x: r.minX, y: r.minY),
                 end: NSPoint(x: vertical ? r.minX : r.maxX, y: r.maxY))
    }

    static func outline(_ path: NSBezierPath, _ color: NSColor, width: CGFloat = 1) {
        color.setStroke()
        path.lineWidth = width
        path.stroke()
    }

    private static func castShadow(_ path: NSBezierPath, blur: CGFloat, drop: CGFloat, opacity: CGFloat) {
        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = pearlColor(0x503949).withAlphaComponent(opacity)
        shadow.shadowBlurRadius = blur
        shadow.shadowOffset = NSSize(width: 0, height: -drop)
        shadow.set()
        NSColor.white.setFill()
        path.fill()
        NSGraphicsContext.restoreGraphicsState()
    }

    static func plate(_ rect: NSRect, radius: CGFloat, colors: [UInt32], system: Bool,
                      blur: CGFloat = 5, drop: CGFloat = 2) {
        let shape = rounded(rect.insetBy(dx: 0.6, dy: 0.6), radius)
        if system {
            NSColor.controlBackgroundColor.setFill()
            shape.fill()
            outline(shape, accessibleOutline, width: prefersHighContrast ? 1.5 : 1)
            return
        }
        castShadow(shape, blur: blur, drop: drop, opacity: 0.18)
        wash(shape, colors: colors)
        gradient(shape, colors: [.white.withAlphaComponent(0.28), .clear, .clear,
                                pearlColor(0x594454).withAlphaComponent(0.025)],
                 start: NSPoint(x: rect.midX, y: rect.minY), end: NSPoint(x: rect.midX, y: rect.maxY))
        outline(shape, pearlColor(0xC1B3BD).withAlphaComponent(0.62), width: 0.8)
        outline(rounded(rect.insetBy(dx: 1.55, dy: 1.55), radius - 1), .white.withAlphaComponent(0.94))
    }

    private static let windowCornerRadius: CGFloat = 26.7

    fileprivate static func windowFramePath(in rect: NSRect, inset: CGFloat = 0) -> NSBezierPath {
        // Keep the corners concentric as the frame, specular edges and result lighting step inward.
        rounded(rect.insetBy(dx: inset, dy: inset), max(0, windowCornerRadius - inset))
    }

    static func frame(in rect: NSRect, header: CGFloat, system: Bool) {
        guard !rect.isEmpty else { return }
        let silhouette = windowFramePath(in: rect)
        let outer = windowFramePath(in: rect, inset: 0.7)
        let inner = windowFramePath(in: rect, inset: 7.5)
        let innerRect = inner.bounds
        if system {
            pearlColor(0xFFFBFD).setFill()
            silhouette.fill()
            clipped(to: silhouette) {
                pearlColor(0xF3EAF5).setFill()
                NSBezierPath(rect: NSRect(x: rect.minX, y: rect.minY, width: rect.width, height: header)).fill()
            }
            outline(outer, accessibleOutline, width: prefersHighContrast ? 1.5 : 1)
        } else {
            // Broad pink, platinum and blue facets remain visible between the two fine specular edges.
            wash(silhouette, colors: [0xCE9CB9, 0xFFF0F7, 0xCEAFC5, 0xE2E9F2, 0xA5B4C7,
                                 0xF9F8FF, 0xA2CDE0, 0xFAEFF1, 0xDBBFC1, 0xC2D8E7, 0xE8CADC])
            let ring = NSBezierPath()
            ring.append(silhouette)
            ring.append(inner)
            ring.windingRule = .evenOdd
            gradient(ring, colors: [.white.withAlphaComponent(0.54), .clear, .white.withAlphaComponent(0.12),
                                    .clear, .white.withAlphaComponent(0.41)],
                     start: NSPoint(x: rect.minX, y: rect.maxY), end: NSPoint(x: rect.maxX, y: rect.minY))
            clipped(to: ring) {
                bloom(color: 0xF1A2C7, opacity: 0.76, center: NSPoint(x: rect.minX, y: rect.minY + 30),
                      radius: rect.width * 0.23)
                bloom(color: 0xA4DFF2, opacity: 0.86, center: NSPoint(x: rect.width * 0.76, y: rect.minY),
                      radius: rect.width * 0.23)
                bloom(color: 0x9FCDF0, opacity: 0.76, center: NSPoint(x: rect.width * 0.16, y: rect.maxY),
                      radius: rect.width * 0.23)
            }
            outline(outer, pearlColor(0xB5A4B6), width: 1)
            outline(windowFramePath(in: rect, inset: 2.1), .white.withAlphaComponent(0.97), width: 1.4)
            outline(windowFramePath(in: rect, inset: 5.8), .white.withAlphaComponent(0.60), width: 0.75)
            wash(inner, colors: [0xFAF0F4, 0xFFFBFA, 0xF4EFF3, 0xFCF8FC, 0xEEF1F7])
            clipped(to: inner) {
                bloom(color: 0xF9C7DB, opacity: 0.32, center: NSPoint(x: rect.minX - 20, y: rect.height * 0.44),
                      radius: min(190, rect.width * 0.22))
                bloom(color: 0xBDDDF0, opacity: 0.30, center: NSPoint(x: rect.maxX, y: rect.height * 0.8),
                      radius: min(245, rect.width * 0.28))
                let bar = NSBezierPath(rect: NSRect(x: innerRect.minX, y: innerRect.minY,
                                                    width: innerRect.width, height: max(1, header - innerRect.minY)))
                wash(bar, colors: [0xF9DFED, 0xFFFBFB, 0xF1E6F3, 0xDDE8F4, 0xFCE7EE])
                gradient(bar, colors: [.white.withAlphaComponent(0.5), .clear, pearlColor(0x99879E).withAlphaComponent(0.08)],
                         start: NSPoint(x: 0, y: innerRect.minY), end: NSPoint(x: 0, y: header))
                clipped(to: bar) {
                    bloom(color: 0xBBDFEF, opacity: 0.44,
                          center: NSPoint(x: rect.width * 0.68, y: -18), radius: header * 2.2)
                    bloom(color: 0xF5C6DF, opacity: 0.43,
                          center: NSPoint(x: rect.width * 0.79, y: header + 19), radius: header * 1.8)
                    gradient(bar, colors: [.clear, .white.withAlphaComponent(0.49), .clear],
                             start: NSPoint(x: rect.width * 0.49, y: 0), end: NSPoint(x: rect.width * 0.52, y: header * 0.45))
                }
            }
            outline(inner, pearlColor(0xA894A9).withAlphaComponent(0.7))
            outline(windowFramePath(in: rect, inset: 8.6), .white.withAlphaComponent(0.96), width: 1.2)
        }
        rule(from: innerRect.minX + 1, to: innerRect.maxX - 1, y: header, system: system)
    }

    static func hero(in rect: NSRect, dividerX: CGFloat, dividerEnd: CGFloat, warning: Bool, system: Bool) {
        let colors: [UInt32] = warning ? [0xF1B2D4, 0xFDD8E1, 0xFFEBE6, 0xF4D8ED] :
                                         [0xD6DEEF, 0xE4E3F1, 0xF5EFF5, 0xE7DFEE]
        plate(rect, radius: 20, colors: colors, system: system, blur: 6, drop: 3)
        if !system {
            clipped(to: rounded(rect.insetBy(dx: 1.5, dy: 1.5), 18.5)) {
                func point(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
                    NSPoint(x: rect.minX + x * rect.width, y: rect.minY + y * rect.height)
                }
                bloom(color: 0xFFF9F4, opacity: 0.66, center: point(0.18, 0.66), radius: rect.height * 0.90)
                bloom(color: warning ? 0xFFCEDA : 0xD2E6F4, opacity: 0.35, center: point(0.76, 0.07),
                      radius: rect.width * 0.34)
                bloom(color: 0xFFF4DF, opacity: 0.55, center: point(0.03, 1.05), radius: rect.height * 1.35)
                bloom(color: 0xD6C2EF, opacity: 0.76, center: point(1.02, 0.94), radius: rect.height * 1.30)
                let silk = NSBezierPath()
                silk.move(to: point(-0.1, 0.92))
                silk.curve(to: point(0.63, 0.06), controlPoint1: point(0.06, 0.22), controlPoint2: point(0.26, -0.32))
                silk.curve(to: point(1.10, 0.12), controlPoint1: point(0.82, 0.28), controlPoint2: point(0.94, 0.31))
                silk.line(to: point(1.10, -0.10))
                silk.line(to: point(-0.10, -0.10))
                silk.close()
                gradient(silk, colors: [.white.withAlphaComponent(0.32), .white.withAlphaComponent(0.03)],
                         start: point(0, 0), end: point(0.88, 0.45))
                let sweep = NSBezierPath()
                sweep.move(to: point(0.33, 1.12))
                sweep.curve(to: point(1.08, 0.44), controlPoint1: point(0.74, 1.04), controlPoint2: point(0.81, 0.68))
                sweep.line(to: point(1.08, 1.12))
                sweep.close()
                gradient(sweep, colors: [.white.withAlphaComponent(0.46), .clear],
                         start: point(0.65, 0.81), end: point(0.70, 1.18))
                // Narrow reflections on the right expose the curve of the surface outside the headline.
                let returnLight = NSBezierPath()
                returnLight.move(to: point(0.67, 1.06))
                returnLight.curve(to: point(1.04, 0.37), controlPoint1: point(0.84, 0.99), controlPoint2: point(0.95, 0.51))
                returnLight.curve(to: point(0.67, 1.06), controlPoint1: point(0.95, 0.47), controlPoint2: point(0.82, 1.06))
                returnLight.close()
                gradient(returnLight, colors: [.clear, .white.withAlphaComponent(0.82), .white.withAlphaComponent(0.30)],
                         start: point(0.70, 0.95), end: point(1.0, 0.50))
                let shoulder = NSBezierPath()
                shoulder.move(to: point(-0.02, 0.74))
                shoulder.curve(to: point(0.15, 0.06), controlPoint1: point(0.035, 0.38), controlPoint2: point(0.09, 0.14))
                shoulder.curve(to: point(-0.02, 0.74), controlPoint1: point(0.085, 0.17), controlPoint2: point(0.03, 0.49))
                shoulder.close()
                gradient(shoulder, colors: [.white.withAlphaComponent(0.74), .clear],
                         start: point(0, 0.6), end: point(0.13, 0.1))
            }
        }
        let divider = NSBezierPath()
        divider.move(to: NSPoint(x: dividerX, y: rect.minY + 20))
        divider.line(to: NSPoint(x: dividerX, y: dividerEnd))
        outline(divider, system ? .separatorColor : pearlColor(0xBE8EA3).withAlphaComponent(0.48), width: 0.8)
    }

    static func informationCard(_ rect: NSRect, hue: UInt32, system: Bool) {
        plate(rect, radius: 16, colors: [0xFFFFFF, 0xFFFCFF, 0xF4F0F5], system: system, blur: 5, drop: 2.5)
        guard !system else { return }
        let face = rounded(rect.insetBy(dx: 1, dy: 1), 15)
        let light = NSPoint(x: rect.minX + rect.width * 0.19, y: rect.minY - 10)
        clipped(to: face) { bloom(color: hue, opacity: 0.065, center: light, radius: rect.width * 0.78) }
        let border = rounded(rect.insetBy(dx: 0.8, dy: 0.8), 15.5)
        border.append(rounded(rect.insetBy(dx: 2.1, dy: 2.1), 14.3))
        border.windingRule = .evenOdd
        clipped(to: border) {
            bloom(color: hue, opacity: 0.44, center: light, radius: rect.width * 0.59)
            bloom(color: 0xA9CDDF, opacity: 0.59, center: NSPoint(x: rect.maxX, y: rect.maxY),
                  radius: rect.width * 0.48)
        }
    }

    static func stepDisc(_ number: Int, in rect: NSRect, system: Bool) {
        plate(rect, radius: rect.width / 2, colors: [0xFFF5FF, 0xE4D2E9, 0xC2ABC8],
              system: system, blur: 2, drop: 1)
        let label = NSAttributedString(string: String(number), attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .bold),
            .foregroundColor: system ? NSColor.labelColor : pearlColor(0x51395D)])
        label.draw(at: NSPoint(x: round(rect.midX - label.size().width / 2), y: round(rect.midY - label.size().height / 2)))
    }

    static func glassControl(_ rect: NSRect, primary: Bool, pressed: Bool, radius: CGFloat) {
        let face = rounded(rect, radius)
        castShadow(face, blur: pressed ? 1 : 4.2, drop: pressed ? 0 : 2, opacity: primary ? 0.26 : 0.17)
        let tones: [UInt32] = primary ? [0x826087, 0x65456F, 0x58385F, 0x715277] :
                                        [0xFFFFFF, 0xF9F6FA, 0xF0ECF2, 0xE1DBE5]
        wash(face, colors: pressed ? Array(tones.reversed()) : tones, vertical: true)
        clipped(to: face) {
            // Top reflection and lower rim receive light independently of the text-bearing center.
            let cap = rounded(NSRect(x: rect.minX + 3, y: rect.minY + 1.3, width: rect.width - 6,
                                     height: rect.height * 0.43), max(2, radius - 2))
            gradient(cap, colors: [.white.withAlphaComponent(primary ? 0.42 : 0.90), .white.withAlphaComponent(0)],
                     start: NSPoint(x: rect.midX, y: cap.bounds.minY), end: NSPoint(x: rect.midX, y: cap.bounds.maxY))
            bloom(color: primary ? 0xD4B5E6 : 0xDAD4E9, opacity: pressed ? 0.08 : 0.23,
                  center: NSPoint(x: rect.maxX - 9, y: rect.maxY + 4), radius: rect.height * 0.72)
        }
        outline(face, primary ? pearlColor(0x5E4269) : pearlColor(0xBEB2C2), width: 0.8)
        outline(rounded(rect.insetBy(dx: 1.2, dy: 1.2), radius - 1), .white.withAlphaComponent(primary ? 0.52 : 0.94), width: 0.7)
    }

    static func rule(from left: CGFloat, to right: CGFloat, y: CGFloat, system: Bool) {
        let line = NSBezierPath()
        line.move(to: NSPoint(x: left, y: y + 0.5))
        line.line(to: NSPoint(x: right, y: y + 0.5))
        outline(line, system ? .separatorColor : pearlColor(0xCFBFCE).withAlphaComponent(0.74), width: 0.75)
        if !system {
            let highlight = NSRect(x: left, y: y + 1, width: max(1, right - left), height: 0.8)
            NSColor.white.withAlphaComponent(0.9).setFill()
            NSBezierPath(rect: highlight).fill()
        }
    }

    static func insetPanel(_ rect: NSRect, radius: CGFloat, system: Bool) {
        let path = rounded(rect, radius)
        if system {
            NSColor.windowBackgroundColor.setFill()
            path.fill()
            outline(path, .separatorColor)
        } else {
            wash(path, colors: [0xF3EDF4, 0xF9F6F9, 0xF2F0F7])
            outline(path, pearlColor(0xDBCFDF), width: 0.7)
        }
    }

    static func glyph(_ name: String, color: NSColor, in rect: NSRect) {
        guard let base = NSImage(systemSymbolName: name, accessibilityDescription: nil) ??
                         NSImage(systemSymbolName: "doc", accessibilityDescription: nil) else { return }
        let config = NSImage.SymbolConfiguration(pointSize: 17, weight: .medium)
            .applying(NSImage.SymbolConfiguration(paletteColors: [color]))
        let icon = base.withSymbolConfiguration(config) ?? base
        let scale = min(rect.width / max(1, icon.size.width), rect.height / max(1, icon.size.height))
        let width = icon.size.width * scale, height = icon.size.height * scale
        icon.draw(in: NSRect(x: rect.midX - width / 2, y: rect.midY - height / 2, width: width, height: height),
                  from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
    }

    static func badge(_ name: String, color: UInt32, in rect: NSRect, system: Bool) {
        let tint = system ? NSColor.labelColor : pearlColor(color)
        let path = rounded(rect, min(9, rect.height / 4))
        if system {
            NSColor.controlBackgroundColor.setFill()
            path.fill()
            outline(path, .separatorColor)
        } else {
            let base = tint.blended(withFraction: 0.87, of: .white) ?? .white
            gradient(path, colors: [.white, base, tint.blended(withFraction: 0.83, of: .white) ?? base],
                     start: NSPoint(x: rect.minX, y: rect.minY), end: NSPoint(x: rect.maxX, y: rect.maxY))
            outline(path, tint.withAlphaComponent(0.23), width: 0.8)
            outline(rounded(rect.insetBy(dx: 1, dy: 1), min(8, rect.height / 4)), .white.withAlphaComponent(0.85))
        }
        let inset = rect.width * 0.22
        glyph(name, color: tint, in: rect.insetBy(dx: inset, dy: inset))
    }

    static func archiveIcon(warning: Bool, showsBadge: Bool = true) -> NSImage {
        NSImage(size: NSSize(width: 132, height: 114), flipped: true) { _ in
            let paper = NSBezierPath()
            paper.move(to: NSPoint(x: 16, y: 6))
            paper.line(to: NSPoint(x: 71, y: 6))
            paper.line(to: NSPoint(x: 98, y: 32))
            paper.line(to: NSPoint(x: 98, y: 92))
            paper.curve(to: NSPoint(x: 91, y: 99), controlPoint1: NSPoint(x: 98, y: 97), controlPoint2: NSPoint(x: 96, y: 99))
            paper.line(to: NSPoint(x: 16, y: 99))
            paper.curve(to: NSPoint(x: 8, y: 91), controlPoint1: NSPoint(x: 11, y: 99), controlPoint2: NSPoint(x: 8, y: 96))
            paper.line(to: NSPoint(x: 8, y: 15))
            paper.curve(to: NSPoint(x: 16, y: 6), controlPoint1: NSPoint(x: 8, y: 9), controlPoint2: NSPoint(x: 11, y: 6))
            paper.close()
            castShadow(paper, blur: 5.5, drop: 4, opacity: 0.38)
            wash(paper, colors: [0xFFFFFF, 0xFAF3FA, 0xE5D8E7, 0xF5EDF6, 0xDCCADC])
            outline(paper, pearlColor(0xAB92AC).withAlphaComponent(0.75), width: 1.8)
            outline(paper, .white.withAlphaComponent(0.96), width: 1)
            let fold = NSBezierPath()
            fold.move(to: NSPoint(x: 71, y: 6))
            fold.line(to: NSPoint(x: 71, y: 25))
            fold.curve(to: NSPoint(x: 78, y: 32), controlPoint1: NSPoint(x: 71, y: 30), controlPoint2: NSPoint(x: 74, y: 32))
            fold.line(to: NSPoint(x: 97, y: 32))
            fold.close()
            castShadow(fold, blur: 2.6, drop: 1.9, opacity: 0.28)
            wash(fold, colors: [0xFFFDFF, 0xFAF2FA, 0xEBDDEB])
            outline(fold, .white.withAlphaComponent(0.94), width: 1.1)

            let track = rounded(NSRect(x: 46, y: 6.5, width: 9.5, height: 46), 1.4)
            wash(track, colors: [0xA79AB1, 0xF7F4FD, 0xA498AC])
            for tooth in 0..<8 {
                let y = 8 + CGFloat(tooth) * 4.4
                wash(rounded(NSRect(x: 46.6, y: y, width: 5.1, height: 2.9), 0.55),
                     colors: [0xF6F2FD, 0xA89BB5, 0x776881], vertical: true)
                wash(rounded(NSRect(x: 50.7, y: y + 2.1, width: 4.3, height: 2.8), 0.55),
                     colors: [0xF4EFF8, 0xAA9CB6, 0x807388], vertical: true)
            }
            let slider = rounded(NSRect(x: 45.4, y: 42, width: 11, height: 13.5), 3.2)
            castShadow(slider, blur: 1.6, drop: 1, opacity: 0.42)
            wash(slider, colors: [0xFCF9FF, 0xB2A5BC, 0xF4F2FB])
            outline(slider, pearlColor(0x95859F), width: 0.65)
            let pull = rounded(NSRect(x: 46, y: 48.5, width: 9.7, height: 17.8), 3)
            pull.append(rounded(NSRect(x: 48.7, y: 56.5, width: 4.3, height: 6), 1.3))
            pull.windingRule = .evenOdd
            castShadow(pull, blur: 1.8, drop: 1.5, opacity: 0.44)
            wash(pull, colors: [0xFFFFFF, 0xC6BBCE, 0xA494B0, 0xF1ECF9])
            outline(pull, pearlColor(0x8C8197), width: 0.65)
            let stamp = NSAttributedString(string: "ZIP", attributes: [
                .font: NSFont.systemFont(ofSize: 17, weight: .bold), .foregroundColor: pearlColor(0x716478)
            ])
            stamp.draw(at: NSPoint(x: 50 - stamp.size().width / 2, y: 75))

            guard showsBadge else { return true }
            let bezel = shield(NSRect(x: 73.5, y: 50, width: 51, height: 57))
            castShadow(bezel, blur: 4, drop: 3, opacity: 0.43)
            wash(bezel, colors: [0xFFFFFF, 0xFFF6F7, 0xD7C8CF, 0xFFFFFF])
            outline(bezel, .white, width: 1.4)
            let face = shield(NSRect(x: 77, y: 53.5, width: 44, height: 50.5))
            wash(face, colors: warning ? [0xFF9299, 0xF85B67, 0xD43F4F, 0xA7283C] :
                                          [0xB3C5DB, 0x8DA9C3, 0x6F88A5, 0x526C87], vertical: true)
            outline(face, pearlColor(warning ? 0xB74652 : 0x7189A3).withAlphaComponent(0.74), width: 0.7)
            clipped(to: face) {
                let glint = NSBezierPath(ovalIn: NSRect(x: 66, y: 39, width: 72, height: 36))
                washGlint(glint)
            }
            let bar = rounded(NSRect(x: 96.9, y: warning ? 66 : 75, width: 4.3, height: warning ? 15.5 : 14), 2.1)
            let dot = NSBezierPath(ovalIn: NSRect(x: 96.65, y: warning ? 85.1 : 66.2, width: 4.8, height: 4.8))
            for mark in [bar, dot] {
                castShadow(mark, blur: 1, drop: 0.8, opacity: 0.28)
                wash(mark, colors: [0xFFFFFF, 0xF6F0F3], vertical: true)
            }
            return true
        }
    }

    private static func washGlint(_ path: NSBezierPath) {
        let r = path.bounds
        gradient(path, colors: [.white.withAlphaComponent(0.35), .white.withAlphaComponent(0.04)],
                 start: NSPoint(x: r.midX, y: r.minY), end: NSPoint(x: r.midX, y: r.maxY))
    }

    private static func bloom(color: UInt32, opacity: CGFloat, center: NSPoint, radius: CGFloat) {
        let tint = pearlColor(color)
        NSGradient(colors: [tint.withAlphaComponent(opacity), tint.withAlphaComponent(0)])?
            .draw(fromCenter: center, radius: 0, toCenter: center, radius: radius, options: [])
    }

    private static func shield(_ rect: NSRect) -> NSBezierPath {
        func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint {
            NSPoint(x: rect.minX + x * rect.width, y: rect.minY + y * rect.height)
        }
        let path = NSBezierPath()
        path.move(to: p(0.5, 0.02))
        path.curve(to: p(0.93, 0.17), controlPoint1: p(0.63, 0.09), controlPoint2: p(0.79, 0.15))
        path.curve(to: p(0.98, 0.24), controlPoint1: p(0.97, 0.18), controlPoint2: p(0.98, 0.20))
        path.line(to: p(0.97, 0.49))
        path.curve(to: p(0.50, 0.98), controlPoint1: p(0.96, 0.71), controlPoint2: p(0.75, 0.88))
        path.curve(to: p(0.03, 0.49), controlPoint1: p(0.25, 0.88), controlPoint2: p(0.04, 0.71))
        path.line(to: p(0.02, 0.24))
        path.curve(to: p(0.07, 0.17), controlPoint1: p(0.02, 0.20), controlPoint2: p(0.03, 0.18))
        path.curve(to: p(0.5, 0.02), controlPoint1: p(0.21, 0.15), controlPoint2: p(0.37, 0.09))
        path.close()
        return path
    }
}

@MainActor final class OrchardPearlLanguageControl: NSSegmentedControl {
    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        if OrchardPearlArt.prefersAccessibleMaterials { super.draw(dirtyRect); return }
        let track = bounds.insetBy(dx: 1.5, dy: 2.5)
        let trackPath = OrchardPearlArt.rounded(track, 11)
        OrchardPearlArt.wash(trackPath, colors: [0xDFD9E5, 0xEEE9F1, 0xF7F2F6], vertical: true)
        OrchardPearlArt.outline(trackPath, pearlColor(0xBDB2C1), width: 0.8)
        let width = (track.width - 2) / 2
        for segment in 0..<segmentCount {
            let r = NSRect(x: track.minX + 1 + CGFloat(segment) * width, y: track.minY + 1,
                           width: width, height: track.height - 2)
            if segment == selectedSegment {
                OrchardPearlArt.plate(r, radius: 9.5, colors: [0xFFFFFF, 0xFDFBFE, 0xEDE6F0],
                                      system: false, blur: 2.2, drop: 1)
            }
            let label = NSAttributedString(string: label(forSegment: segment) ?? "", attributes: [
                .font: NSFont.systemFont(ofSize: 13, weight: segment == selectedSegment ? .semibold : .regular),
                .foregroundColor: pearlColor(0x392F3F)
            ])
            label.draw(at: NSPoint(x: round(r.midX - label.size().width / 2), y: round(r.midY - label.size().height / 2)))
        }
    }
}

@MainActor final class OrchardPearlButton: NSButton {
    enum AppearanceRole { case primary, secondary }
    var appearanceRole: AppearanceRole = .secondary
    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        if OrchardPearlArt.prefersAccessibleMaterials { super.draw(dirtyRect); return }
        let down = cell?.isHighlighted == true
        let r = bounds.insetBy(dx: 2, dy: 3.5).offsetBy(dx: 0, dy: down ? 1 : 0)
        let primary = appearanceRole == .primary
        OrchardPearlArt.glassControl(r, primary: primary, pressed: down, radius: 12)
        let tint = primary ? NSColor.white : pearlColor(0x44384D)
        let label = NSAttributedString(string: title, attributes: [
            .font: font ?? NSFont.systemFont(ofSize: 14, weight: .semibold), .foregroundColor: tint
        ])
        let iconSpace: CGFloat = image == nil ? 0 : 23
        var x = round(r.midX - (label.size().width + iconSpace) / 2)
        if image != nil {
            OrchardPearlArt.glyph("doc.text.magnifyingglass", color: tint,
                                  in: NSRect(x: x, y: r.midY - 8, width: 17, height: 16))
            x += iconSpace
        }
        label.draw(at: NSPoint(x: x, y: round(r.midY - label.size().height / 2)))
    }
}

private func pearlColor(_ rgb: UInt32) -> NSColor {
    NSColor(srgbRed: CGFloat((rgb >> 16) & 255) / 255, green: CGFloat((rgb >> 8) & 255) / 255,
            blue: CGFloat(rgb & 255) / 255, alpha: 1)
}
