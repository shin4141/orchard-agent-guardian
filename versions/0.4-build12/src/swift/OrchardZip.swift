import AppKit
import CryptoKit
import Darwin
import Foundation
import UniformTypeIdentifiers

// Same implementation used by the pinned R1 direct-child port.
func hash54(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

enum OrchardFault: String, Error { case input, changed, identity, result }

struct OrchardWorkerIdentity {
    let app: URL
    let executable: URL
    let executableSHA256: String
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
            }
        }
        let actual = try SentinelRuntime.inventoryPaths(in: app)
        let required: Set<String> = ["Contents/MacOS/OrchardZipWorker", "Contents/Resources/warehouse_worker_entry.py",
            "Contents/Resources/feed_adapter.py", "Contents/Resources/warehouse_code/warehouse.py", "Contents/Resources/bounded_reader.py", "Contents/Resources/POLICY.json", "Contents/Resources/r1_snapshot.py", "Contents/Resources/inspection.py",
            "Contents/Resources/threat_db.py", "Contents/Resources/warehouse/current.json", "Contents/Resources/warehouse/g-a5e38cbf56364a3ba6deac193ff7652c/manifest.json", "Contents/Resources/warehouse/g-a5e38cbf56364a3ba6deac193ff7652c/hashes.sqlite3", "Contents/Resources/warehouse/g-a5e38cbf56364a3ba6deac193ff7652c/suppression.json"]
        guard actual == expected, required.isSubset(of: expected), let sha = executableHash else { throw OrchardFault.identity }
        return OrchardWorkerIdentity(app: app, executable: URL(fileURLWithPath: try SentinelRuntime.physicalPath(app.appendingPathComponent("Contents/MacOS/OrchardZipWorker"), inside: app)), executableSHA256: sha,
            entryPath: try SentinelRuntime.physicalPath(app.appendingPathComponent("Contents/Resources/warehouse_worker_entry.py"), inside: app),
            snapshotPath: try SentinelRuntime.physicalPath(app.appendingPathComponent("Contents/Resources/warehouse/current.json"), inside: app))
    }

    func runtime(mode: OrchardWarehouseMode) -> R1WorkerRuntime {
        let bundle = Bundle.main.bundleURL
        return R1WorkerRuntime(executable: executable,
            argvTail: ["-I", "-S", "-B", entryPath,
                       "--fd=0", "--manifest=" + snapshotPath, "--verification-mode=" + mode.rawValue],
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
    let mode: OrchardWarehouseMode
    init(url: URL, mode: OrchardWarehouseMode = .live) { self.url = url; self.mode = mode }

    func run() throws -> Data {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw OrchardFault.input }
        defer { close(fd) }
        var before = stat(), after = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_nlink == 1,
              before.st_size > 0, before.st_size <= 8_388_608 else { throw OrchardFault.input }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        let bytes = try handle.read(upToCount: 8_388_609) ?? Data()
        guard bytes.count == before.st_size, fstat(fd, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw OrchardFault.changed }
        // Anonymous owned copy pins exactly the bytes whose SHA is displayed.
        var temporary = Array((NSTemporaryDirectory() + "orchard-input-XXXXXX").utf8CString)
        let owned = mkstemp(&temporary)
        guard owned >= 0 else { throw OrchardFault.input }
        defer { close(owned) }
        guard unlink(temporary) == 0, fchmod(owned, 0o600) == 0 else { throw OrchardFault.input }
        let copy = FileHandle(fileDescriptor: owned, closeOnDealloc: false)
        try copy.write(contentsOf: bytes)
        guard lseek(owned, 0, SEEK_SET) == 0 else { throw OrchardFault.input }
        let identity = try OrchardWorkerIdentity.load()
        let port = R1WorkerProcessPort(runtime: identity.runtime(mode: mode))
        resourcesQuiescent = false
        defer { resourcesQuiescent = port.resourcesQuiescent }
        let receipt = try port.runOnce(inputFD: owned, inputBytes: Int64(bytes.count), inputSHA256: hash54(bytes),
            deadline: 10.0, cancellation: cancellation)
        guard port.resourcesQuiescent else { throw OrchardFault.result }
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
@MainActor func orchardZipPresentation(receipt: Data, name: String) throws -> [String: String] {
    let now = Date()
    let review = R1ReviewSession(receiptData: receipt, now: now, deadline: now.addingTimeInterval(300))
    let snapshot = review.snapshot(now: now)
    guard let outer = try JSONSerialization.jsonObject(with: receipt) as? [String: Any],
          let report = outer["engine_report"] as? [String: Any], let rawTI = report["threat_intelligence"],
          let ti = try? JSONDecoder().decode(R1ThreatIntelligence.self, from: JSONSerialization.data(withJSONObject: rawTI)),
          ti.valid, !snapshot.lines.contains(where: { $0.hasPrefix("worker/結果未資格:") }) else { throw OrchardFault.result }
    let headline: String
    switch ti.status {
    case "KNOWN_HASH_MATCH": headline = "対象DBの既知SHAに一致しました"
    case "NO_MATCH_IN_COVERED_DB": headline = "対象DB内に一致はありません（安全の保証ではありません）"
    case "DB_NOT_UPDATED": headline = "DBの更新が必要です。不一致を判定できません"
    default: headline = "検査を完了できない項目があります"
    }
    let r1 = snapshot.promptInjection == "DETECTED" ? "疑わしい指示を検出しました" :
        (snapshot.promptInjection == "NOT_DETECTED" ? "対象規則内で疑わしい指示は検出されませんでした" : "指示の検査を完了できませんでした")
    var lines = ["ファイル: " + orchardVisible(name), r1, ""] + ti.displayLines
    lines += ["", "検査結果の詳細:"] + snapshot.lines.filter { line in
        ["入力SHA256:", "件数:", "検出根拠:", "非信頼データ /", "UNKNOWN", "対応範囲と限界:", "限界:"].contains { prefix in
            line.hasPrefix(prefix)
        }
    }
    return ["headline": (ti.database.verification_mode == "LIVE" ? "" : "【検証】") + headline,
            "body": lines.joined(separator: "\n"), "promptInjection": snapshot.promptInjection]
}

@MainActor final class OrchardZipController: NSObject {
    let view = NSStackView()
    private let choose = NSButton(title: "ZIPを選んで照合", target: nil, action: nil)
    private let cancel = NSButton(title: "照合を中止", target: nil, action: nil)
    private let status = NSTextField(wrappingLabelWithString: "ZIPはまだ選ばれていません")
    private let instructionResult = NSTextField(wrappingLabelWithString: "指示の検査はまだ行っていません")
    private let instructionIcon = NSImageView()
    private let output = NSTextView()
    private let repeatCurrent = NSButton(title: "通常で再照合", target: nil, action: nil)
    private var lastURL: URL?
    private var activeJob: OrchardZipJob?
    private var terminationReply: ((Bool) -> Void)?

    override init() {
        super.init()
        let title = NSTextField(labelWithString: "ZIPのSHA照合")
        title.font = .systemFont(ofSize: 20, weight: .semibold)
        let description = NSTextField(wrappingLabelWithString: "ZIP内のファイルを既知SHAと照合し、疑わしい指示も検査します。ファイルを展開・実行せず、ネットワークへ送信しません。")
        choose.target = self; choose.action = #selector(selectZip)
        choose.bezelStyle = .rounded
        choose.setAccessibilityIdentifier("orchard.zip.select")
        cancel.target = self; cancel.action = #selector(cancelInspection)
        cancel.bezelStyle = .rounded
        cancel.isEnabled = false
        status.font = .systemFont(ofSize: 13, weight: .medium)
        status.maximumNumberOfLines = 3
        status.setAccessibilityIdentifier("orchard.zip.status")
        instructionResult.font = .systemFont(ofSize: 16, weight: .semibold)
        instructionResult.maximumNumberOfLines = 3
        instructionResult.setContentCompressionResistancePriority(.required, for: .vertical)
        instructionResult.setAccessibilityIdentifier("orchard.zip.instructionResult")
        instructionIcon.image = NSImage(systemSymbolName: "exclamationmark.triangle.fill", accessibilityDescription: "警告")
        instructionIcon.imageScaling = .scaleProportionallyUpOrDown
        instructionIcon.contentTintColor = .systemRed
        instructionIcon.isHidden = true
        instructionIcon.setAccessibilityIdentifier("orchard.zip.warningIcon")
        let instructionSummary = NSStackView(views: [instructionIcon, instructionResult])
        instructionSummary.alignment = .centerY
        instructionSummary.spacing = 10
        repeatCurrent.target = self; repeatCurrent.action = #selector(reinspectNormal)
        let repeatControls = NSStackView(views: [repeatCurrent])
        repeatControls.spacing = 6
        for button in [repeatCurrent] {
            button.bezelStyle = .rounded; button.font = .systemFont(ofSize: 11); button.isEnabled = false
        }
        repeatCurrent.setAccessibilityIdentifier("orchard.zip.normal")
        let buttons = NSStackView(views: [choose, cancel])
        buttons.spacing = 10
        output.isEditable = false; output.isSelectable = true
        output.isRichText = false
        output.isAutomaticLinkDetectionEnabled = false
        output.font = .systemFont(ofSize: 12)
        output.textContainerInset = NSSize(width: 10, height: 12)
        output.autoresizingMask = [.width]
        output.textContainer?.widthTracksTextView = true
        output.setAccessibilityIdentifier("orchard.zip.result")
        output.string = "実SHA300,000 unique件の限定倉庫（旧100,000件を保持・新規200,000件追加）を参照します。\n\n最新30万件や全期間の完全収録ではありません。一致なしは安全・開封・実行許可を意味しません。\n\n生成時刻・取得時刻を表示し、保存済み倉庫内の一致・未一致を照合します。25時間超のみでは保留しません。DBの整合性異常・検査不能・許諾撤回などは保留します。\n\n更新時は互換性を確認して既存の登録・未確認変更を引き継ぎます。旧版が監視中の場合は保留します。監視登録は1フォルダです。登録後に手動で監視を開始します。自動更新・ログイン登録は無効です。"
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.documentView = output
        view.orientation = .vertical; view.alignment = .leading; view.spacing = 14
        for element in [title, description, buttons, repeatControls, instructionSummary, status, scroll] { view.addArrangedSubview(element) }
        NSLayoutConstraint.activate([
            instructionIcon.widthAnchor.constraint(equalToConstant: 28),
            instructionIcon.heightAnchor.constraint(equalToConstant: 28),
            instructionSummary.widthAnchor.constraint(equalTo: view.widthAnchor),
            scroll.widthAnchor.constraint(equalTo: view.widthAnchor),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 330),
            status.widthAnchor.constraint(equalTo: view.widthAnchor),
            description.widthAnchor.constraint(equalTo: view.widthAnchor)
        ])
    }

    @objc private func selectZip() {
        guard activeJob == nil else { return }
        let picker = NSOpenPanel()
        picker.message = "照合するZIPを1つ選択してください"
        picker.prompt = "このZIPを照合"
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

    private func inspect(_ url: URL, mode: OrchardWarehouseMode = .live) {
        guard activeJob == nil else { return }
        lastURL = url
        let job = OrchardZipJob(url: url, mode: mode)
        activeJob = job
        choose.isEnabled = false; cancel.isEnabled = true
        for button in [repeatCurrent] { button.isEnabled = false }
        status.stringValue = "照合中: " + visible(url.lastPathComponent)
        showInstructionResult(nil, pending: "指示の検査中です")
        output.string = "最大8 MiB・128項目。検査は最大10秒で停止します。"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try job.run() }
            DispatchQueue.main.async { self?.finished(job, result: result) }
        }
    }

    private func visible(_ text: String) -> String {
        orchardVisible(text)
    }

    private func finished(_ job: OrchardZipJob, result: Result<Data, Error>) {
        guard activeJob === job else { return }
        activeJob = nil
        defer {
            if let reply = terminationReply {
                terminationReply = nil
                reply(job.resourcesQuiescent)
            }
        }
        choose.isEnabled = true; cancel.isEnabled = false
        for button in [repeatCurrent] { button.isEnabled = lastURL != nil }
        if job.cancellation.requested {
            showInstructionResult(nil)
            status.stringValue = "照合を中止しました"
            output.string = "結果は採用していません。"
            return
        }
        do {
            let receipt = try result.get()
            let presentation = try orchardZipPresentation(receipt: receipt, name: job.url.lastPathComponent)
            showInstructionResult(presentation["promptInjection"])
            status.stringValue = presentation["headline"]!
            output.string = presentation["body"]!
        } catch {
            showInstructionResult(nil)
            status.stringValue = "検査不能・結果を採用できません"
            output.string = "ZIPの上限・入力の変更・実行環境または検査結果を確認できませんでした。\n安全・不一致とは判定しません。\n詳細: " + visible(String(describing: error))
        }
    }

    private func showInstructionResult(_ result: String?, pending: String? = nil) {
        let detected = result == "DETECTED"
        instructionIcon.isHidden = !detected
        instructionResult.font = .systemFont(ofSize: detected ? 24 : 16,
                                             weight: detected ? .bold : .semibold)
        instructionResult.textColor = detected ? .systemRed : .labelColor
        instructionResult.stringValue = detected ? "疑わしい指示を検出しました" :
            (result == "NOT_DETECTED" ? "対象規則内で疑わしい指示は検出されませんでした" :
                (pending ?? "指示の検査を完了できませんでした"))
    }

    @objc private func cancelInspection() {
        activeJob?.cancellation.request("HUMAN_CANCEL")
        cancel.isEnabled = false
        status.stringValue = "中止と子プロセスの終了を確認中"
    }

    func cancelForTermination() { activeJob?.cancellation.request("APP_TERMINATION") }

    func deferTermination(_ reply: @escaping (Bool) -> Void) -> Bool {
        guard activeJob != nil else { return false }
        terminationReply = reply
        cancelForTermination()
        status.stringValue = "検査を中止し、子プロセスの終了を確認してからアプリを終了します"
        return true
    }
}
