import AppKit
import Darwin
import Foundation

@_silgen_name("flock")
private func cFlock(_ descriptor: Int32, _ operation: Int32) -> Int32

// Local companion for the isolated Python polling PoC; it never executes watched files.
private struct Options {
    let root: String
    let stateDir: String
    let registrationPath: String
    let registrationError: String?
    let registrationIntake: RegistrationIntake?
    let interval: TimeInterval
    let inspect: Bool
    let previewWindow: Bool
    let pythonPath: String?
    let detectorPath: String?
    let runtimeError: String?
    let runtimeManifestSHA256: String?
    let panelDebounce: TimeInterval
}

private struct ChangeRow {
    let id: String
    let path: String
    let filename: String
    let kind: String
    let detectedAt: Date?
    let lastActivityEpoch: Double
    let dismissed: Bool
}

private enum DisplayState {
    case unregistered
    case running([ChangeRow])
    case stopped([ChangeRow])
    case unknown([ChangeRow], String)

    var title: String {
        switch self {
        case .unregistered: return "🍎⏸ 未登録"
        case .running: return activeRows.isEmpty ? "🍎 見守り" : "🍎🔴 要確認 \(activeRows.count)件"
        case .stopped: return activeRows.isEmpty ? "🍎⏸ 停止中" : "🍎⏸🔴\(activeRows.count) 停止中"
        case .unknown(_, let reason): return activeRows.isEmpty ? (reason.hasPrefix("[登録確認]") ? "🍎⚠️ 登録を確認" : "🍎⚠️ 状態不明") : "🍎⚠️🔴\(activeRows.count) 状態不明"
        }
    }

    var activeRows: [ChangeRow] { rows.filter { !$0.dismissed } }

    var rows: [ChangeRow] {
        switch self {
        case .unregistered: return []
        case .running(let rows), .stopped(let rows), .unknown(let rows, _): return rows
        }
    }

    var permitsReview: Bool {
        switch self { case .running, .stopped: return true; default: return false }
    }

    var isRunning: Bool {
        if case .running = self { return true }
        return false
    }
}

private func usage() -> Never {
    fputs("Usage: OrchardSentinelMenu [--root PROJECT --state-dir STATE] [--registration-file FILE] [--python PYTHON --detector SENTINEL_PY] [--interval SECONDS] [--panel-debounce SECONDS] [--inspect] [--preview-window]\n", stderr)
    exit(64)
}

private func canonicalPath(_ path: String) -> String {
    let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
    return resolved.count > 1 && resolved.hasSuffix("/") ? String(resolved.dropLast()) : resolved
}

private func optionsFromArguments() -> Options {
    let arguments = Array(CommandLine.arguments.dropFirst())
    var root: String?
    var stateDir: String?
    var interval: TimeInterval = 1.0
    var panelDebounce: TimeInterval = 2.0
    var inspect = false
    var previewWindow = false
    var pythonPath: String?
    var detectorPath: String?
    var registrationPath = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Orchard/registration.json").path
    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--root":
            index += 1
            guard index < arguments.count else { usage() }
            root = arguments[index]
        case "--state-dir":
            index += 1
            guard index < arguments.count else { usage() }
            stateDir = arguments[index]
        case "--registration-file":
            index += 1
            guard index < arguments.count else { usage() }
            registrationPath = arguments[index]
        case "--interval":
            index += 1
            guard index < arguments.count,
                  let number = Double(arguments[index]),
                  number.isFinite, number >= 0.1, number <= 60 else { usage() }
            interval = number
        case "--panel-debounce":
            index += 1
            guard index < arguments.count,
                  let number = Double(arguments[index]),
                  number.isFinite, number >= 0.1, number <= 60 else { usage() }
            panelDebounce = number
        case "--inspect":
            inspect = true
        case "--preview-window":
            previewWindow = true
        case "--python":
            index += 1
            guard index < arguments.count else { usage() }
            pythonPath = arguments[index]
        case "--detector":
            index += 1
            guard index < arguments.count else { usage() }
            detectorPath = arguments[index]
        default:
            usage()
        }
        index += 1
    }
    if (root == nil) != (stateDir == nil) { usage() }
    let selectedRegistration = URL(fileURLWithPath: registrationPath).standardizedFileURL.path
    var registrationError: String?
    var intake: RegistrationIntake?
    let runtime = try? SentinelRuntime.load()
    if root == nil {
        let resolved = registrationContinuity("resolve", path: selectedRegistration)
        intake = resolved
        if resolved.status == "READY" {
            root = resolved.root; stateDir = resolved.stateDir
        } else if resolved.status != "UNREGISTERED" {
            registrationError = "[登録確認] " + resolved.message
        }
    }
    let hasOverride = pythonPath != nil || detectorPath != nil
    let manualPair = Bundle.main.bundleURL.pathExtension != "app" && pythonPath != nil && detectorPath != nil
    let runtimeError: String? = (hasOverride ? !manualPair : runtime == nil)
        ? "同梱runtimeの同一性を確認できません。パッケージでは外部Pythonへの差し替えを許可しません。" : nil
    return Options(
        root: root.map(canonicalPath) ?? "",
        stateDir: stateDir.map(canonicalPath) ?? "",
        registrationPath: selectedRegistration,
        registrationError: registrationError,
        registrationIntake: intake,
        interval: interval,
        inspect: inspect,
        previewWindow: previewWindow,
        pythonPath: runtimeError == nil ? (manualPair ? pythonPath.map(canonicalPath) : runtime?.python) : nil,
        detectorPath: runtimeError == nil ? (manualPair ? detectorPath.map(canonicalPath) : runtime?.detector) : nil,
        runtimeError: runtimeError,
        runtimeManifestSHA256: runtime?.manifestSHA256,
        panelDebounce: panelDebounce
    )
}

private func safeLabel(_ raw: String) -> String {
    let cleaned = raw.unicodeScalars.map { scalar -> String in
        CharacterSet.controlCharacters.contains(scalar) ? "�" : String(scalar)
    }.joined()
    let prefix = String(cleaned.prefix(160))
    return cleaned.count > 160 ? prefix + "…" : prefix
}

private func readObject(_ path: String) throws -> [String: Any] {
    let url = URL(fileURLWithPath: path)
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
    guard values.isRegularFile == true, values.isSymbolicLink != true,
          let size = values.fileSize, size <= 8 * 1024 * 1024 else {
        throw NSError(domain: "SentinelMenu", code: 1)
    }
    let data = try Data(contentsOf: url)
    guard data.count <= 8 * 1024 * 1024,
          let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw NSError(domain: "SentinelMenu", code: 2)
    }
    return object
}

private func monitorLeaseHeld(_ path: String) -> Bool? {
    let fd = path.withCString { Darwin.open($0, O_RDWR | O_NOFOLLOW | O_CLOEXEC) }
    if fd < 0 { return errno == ENOENT ? false : nil }
    defer { _ = Darwin.close(fd) }
    var info = stat()
    guard Darwin.fstat(fd, &info) == 0,
          info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
          info.st_uid == Darwin.getuid(), info.st_mode & 0o077 == 0 else { return nil }
    if cFlock(fd, LOCK_EX | LOCK_NB) == 0 {
        _ = cFlock(fd, LOCK_UN)
        return false
    }
    return errno == EWOULDBLOCK ? true : nil
}

private func nativeMonitorStatus(root: String, stateDir: String) -> [String: Any] {
    let path = stateDir + "/monitor.json"
    let heartbeat: [String: Any]?
    do {
        heartbeat = FileManager.default.fileExists(atPath: path) ? try readObject(path) : nil
    } catch {
        return ["state": "UNKNOWN", "reason": "INVALID_HEARTBEAT"]
    }
    guard let held = monitorLeaseHeld(stateDir + "/monitor.lock") else {
        return ["state": "UNKNOWN", "reason": "INVALID_MONITOR_LOCK"]
    }
    guard let heartbeat else {
        return ["state": held ? "UNKNOWN" : "STOPPED",
                "reason": held ? "LEASE_WITHOUT_HEARTBEAT" : "NO_WATCHER"]
    }
    guard heartbeat["version"] as? Int == 1,
          let savedRoot = heartbeat["root"] as? String, canonicalPath(savedRoot) == root,
          let pid = heartbeat["pid"] as? Int, pid > 0,
          let interval = heartbeat["interval"] as? NSNumber,
          let lastScan = heartbeat["last_scan_epoch"] as? NSNumber,
          let token = heartbeat["run_token"] as? String,
          token.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
          interval.doubleValue.isFinite, interval.doubleValue > 0,
          lastScan.doubleValue.isFinite, lastScan.doubleValue >= 0 else {
        return ["state": "UNKNOWN", "reason": "INVALID_HEARTBEAT"]
    }
    if !held {
        return ["state": "STOPPED", "reason": "WATCHER_EXITED",
                "pid": pid, "run_token": token]
    }
    let age = Date().timeIntervalSince1970 - lastScan.doubleValue
    if age < 0 || age > max(5.0, 3 * interval.doubleValue) {
        return ["state": "UNKNOWN", "reason": "STALE_SCAN",
                "pid": pid, "run_token": token]
    }
    return ["state": "RUNNING", "reason": "FRESH_SCAN_AND_LEASE",
            "pid": pid, "run_token": token, "last_scan_epoch": lastScan.doubleValue]
}

private struct NoticeReadFailure: Error {
    let reason: UIMessage
}

private func readNoticeRows(options: Options, root: String, stateDir: String) -> Result<[ChangeRow], NoticeReadFailure> {
    let (status, payload, _) = runDetector(options: options, root: root, stateDir: stateDir, command: "notice-list")
    if payload?["result"] as? String == "NOTICE_BUSY" {
        return .failure(NoticeReadFailure(reason: UIM("review.registration_busy", "監視が保存状態を更新中です。少し待ってから、未確認の変更をもう一度開いてください。")))
    }
    let unverified = NoticeReadFailure(reason: UIM("monitor.notice_unverified", "未確認台帳を読み取れません。監視画面で状態を再確認してください。"))
    guard status == 0, payload?["result"] as? String == "READY",
          let entries = payload?["rows"] as? [[String: Any]], entries.count <= 1025 else {
        return .failure(unverified)
    }
    var rows: [ChangeRow] = []
    var ids = Set<String>()
    for entry in entries {
        guard let id = entry["id"] as? String,
              id.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil, ids.insert(id).inserted,
              let path = entry["path"] as? String, let kind = entry["kind"] as? String,
              let detected = entry["detected_epoch"] as? Double, detected.isFinite, detected >= 0,
              let activity = entry["last_activity_epoch"] as? Double, activity.isFinite, activity >= detected,
              let dismissed = entry["dismissed"] as? Bool else { return .failure(unverified) }
        rows.append(ChangeRow(id: id, path: safeLabel(path), filename: safeLabel((path as NSString).lastPathComponent),
                              kind: safeLabel(kind),
                              detectedAt: detected > 0 ? Date(timeIntervalSince1970: detected) : nil,
                              lastActivityEpoch: activity, dismissed: dismissed))
    }
    return .success(rows)
}

private struct NoticeFileStamp: Equatable {
    let device: dev_t
    let inode: ino_t
    let bytes: off_t
    let seconds: Int
    let nanos: Int
}

private func noticeFileStamps(_ stateDir: String) -> [NoticeFileStamp?]? {
    var stamps: [NoticeFileStamp?] = []
    for name in ["baseline.json", "pending.json", "history.json", "accept-journal.json"] {
        var info = stat()
        if lstat(stateDir + "/" + name, &info) != 0 {
            guard errno == ENOENT else { return nil }
            stamps.append(nil)
            continue
        }
        guard info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_uid == Darwin.getuid(), info.st_mode & 0o077 == 0 else { return nil }
        stamps.append(NoticeFileStamp(device: info.st_dev, inode: info.st_ino, bytes: info.st_size,
                                      seconds: info.st_mtimespec.tv_sec, nanos: info.st_mtimespec.tv_nsec))
    }
    return stamps
}

private func loadDisplayState(root: String, stateDir: String,
                              registrationError: String?, monitor: [String: Any]?, registrationIssue: UIMessage? = nil,
                              presentation: ((UIMessage) -> Void)? = nil,
                              notices: () -> Result<[ChangeRow], NoticeReadFailure>) -> DisplayState {
    func unknown(_ rows: [ChangeRow], _ message: UIMessage) -> DisplayState {
        presentation?(message)
        return .unknown(rows, message.raw)
    }

    if let registrationError {
        presentation?(registrationIssue ?? .verbatim(registrationError))
        return .unknown([], registrationError)
    }
    if root.isEmpty || stateDir.isEmpty { return .unregistered }
    let baselinePath = stateDir + "/baseline.json"
    if !FileManager.default.fileExists(atPath: baselinePath) { return unknown([], UIM("monitor.reason.baseline_missing", "[登録確認] 信頼基準が見つかりません。元の保存先を確認してください。自動初期化は行いません。")) }
    switch notices() {
    case .failure(let failure):
        return unknown([], failure.reason)
    case .success(let rows):
        switch monitor?["state"] as? String {
        case "RUNNING": return .running(rows)
        case "STOPPED": return .stopped(rows)
        case "UNKNOWN": return unknown(rows, UIM("monitor.reason.not_running", "監視プロセスの実稼働を確認できません"))
        default: return unknown(rows, UIM("monitor.reason.unreadable", "監視プロセスの状態を読み取れません"))
        }
    }
}

private func timestamp(_ date: Date?) -> String {
    guard let date else { return "検出時刻未記録（旧状態）" }
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "ja_JP")
    formatter.timeZone = .current
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss zzz"
    return formatter.string(from: date)
}

private func lines(for state: DisplayState) -> [String] {
    switch state {
    case .unregistered:
        return ["停止中・プロジェクト未登録", "登録するまで監視も信頼基準の作成も行いません"]
    case .running(let rows), .stopped(let rows):
        let phase = state.isRunning ? "監視中" : "停止中"
        let closed = rows.count - state.activeRows.count
        return ["\(phase)・未確認の変更: \(rows.count)件"] + state.activeRows.map {
            "\($0.path) · \($0.kind) · \(timestamp($0.detectedAt))"
        } + (closed > 0 ? ["通知を閉じた未確認の変更: \(closed)件"] : [])
          + [rows.isEmpty ? "未確認の変更はありません" : "未確認の変更は残っています",
             "自動承認・復元は行いません"]
    case .unknown(let rows, let reason):
        let closed = rows.count - state.activeRows.count
        return [rows.isEmpty ? "登録・未確認件数を確認できません（未登録とは判定しません）" : "状態不明・未確認の変更: \(rows.count)件"] + state.activeRows.map {
            "\($0.path) · \($0.kind) · \(timestamp($0.detectedAt))"
        } + (closed > 0 ? ["通知を閉じた未確認の変更: \(closed)件"] : []) + [reason, "監視中とは表示しません"]
    }
}

private func localizedLines(for state: DisplayState, reasonMessage: UIMessage?) -> [String] {
    let active = state.activeRows
    let closed = state.rows.count - active.count
    let dismissed = closed > 0
        ? [UIL("monitor.notice_dismissed_count", "通知を閉じた未確認の変更: {p0}件", ["p0": UIValue(closed)])] : []
    switch state {
    case .unregistered:
        return [UIL("monitor.unregistered.detail", "停止中・プロジェクト未登録"), UIL("monitor.unregistered.no_baseline", "登録するまで監視も信頼基準の作成も行いません")]
    case .running(let rows), .stopped(let rows):
        let phase = state.isRunning ? UIL("monitor.phase.running", "監視中") : UIL("monitor.phase.stopped", "停止中")
        return [UIL("monitor.pending.count", "{p0}・未確認の変更: {p1}件", ["p0": UIValue(phase), "p1": UIValue(rows.count)])] + active.map {
            "\($0.path) · \($0.kind) · \(localizedTimestamp($0.detectedAt))"
        } + dismissed + [rows.isEmpty ? UIL("monitor.pending.none", "未確認の変更はありません") : UIL("monitor.pending.remain", "未確認の変更は残っています"),
             UIL("monitor.pending.no_auto_accept", "自動承認・復元は行いません")]
    case .unknown(let rows, let reason):
        return [rows.isEmpty ? UIL("monitor.unknown.not_unregistered", "登録・未確認件数を確認できません（未登録とは判定しません）") : UIL("monitor.unknown.count", "状態不明・未確認の変更: {p0}件", ["p0": UIValue(rows.count)])] + active.map {
            "\($0.path) · \($0.kind) · \(localizedTimestamp($0.detectedAt))"
        } + dismissed + [reasonMessage?.text ?? UIL("monitor.reason.generic", reason), UIL("monitor.unknown.no_running_claim", "監視中とは表示しません")]
    }
}

private func runDetector(options: Options, root: String, stateDir: String,
                         command: String, arguments: [String] = []) -> (Int32, [String: Any]?, String) {
    guard options.runtimeError == nil, let python = options.pythonPath, let detector = options.detectorPath,
          Bundle.main.bundleURL.pathExtension != "app" || SentinelRuntime.validates(python: python, script: detector),
          !root.isEmpty, !stateDir.isEmpty else {
        return (64, nil, "監視ヘルパーの場所またはプロジェクトが未設定です")
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: python)
    process.arguments = ["-I", "-S", "-B", detector, command, "--root", root, "--state-dir", stateDir] + arguments
    process.environment = SentinelRuntime.environment
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = pipe
    do {
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let raw = String(decoding: data, as: UTF8.self)
        let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return (process.terminationStatus, object, raw)
    } catch {
        return (70, nil, "監視ヘルパーを起動できません")
    }
}

private func localizedTitle(_ state: DisplayState) -> String {
        let active = state.activeRows.count
        switch state {
        case .unregistered: return UIL("monitor.state.unregistered", "🍎⏸ 未登録")
        case .running: return active == 0 ? UIL("monitor.state.watching", "🍎 見守り") : UIL("monitor.state.pending", "🍎🔴 要確認 {p0}件", ["p0": UIValue(active)])
        case .stopped: return active == 0 ? UIL("monitor.state.stopped", "🍎⏸ 停止中") : UIL("monitor.state.stopped_pending", "🍎⏸🔴{p0} 停止中", ["p0": UIValue(active)])
        case .unknown(_, let reason): return active == 0 ? (reason.hasPrefix("[登録確認]") ? UIL("monitor.state.verify_registration", "🍎⚠️ 登録を確認") : UIL("monitor.state.unknown", "🍎⚠️ 状態不明")) : UIL("monitor.state.unknown_pending", "🍎⚠️🔴{p0} 状態不明", ["p0": UIValue(active)])
        }
    }

private struct NoticeSnapshotCache {
    let root: String
    let stateDir: String
    let stamps: [NoticeFileStamp?]
    let rows: [ChangeRow]
}

private struct MonitorPresentationSnapshot {
    let state: DisplayState
    let reason: UIMessage?
    let osRegistration: SentinelRegistration
    let policy: SentinelPolicyView?
    let root: String
    let registrationError: String?
    let action: OrchardMonitorAction
    let runtimeError: String?
    let manualRuntime: Bool
}
private func localizedTimestamp(_ date: Date?) -> UIMessage {
    guard let date else { return UIM("monitor.time_missing", "検出時刻未記録（旧状態）") }
    return .verbatim(timestamp(date))
}
private func localizedKind(_ kind: String) -> UIMessage {
    switch kind {
    case "ADDED": return UIM("monitor.kind.added", "追加")
    case "DELETED": return UIM("monitor.kind.deleted", "削除")
    case "CHANGED": return UIM("monitor.kind.changed", "変更")
    case "UNINSPECTABLE": return UIM("monitor.kind.uninspectable", "比較できない状態")
    default: return UIM("monitor.kind.other", "状態変更")
    }
}

// The startup window uses the same material, controls and archive artwork as the ZIP sheet.
enum OrchardMonitorAction {
    case chooseFolder, start, stop, reviewRegistration, reviewOtherRegistration, checkMonitor

    var label: UIMessage {
        switch self {
        case .chooseFolder: return UIM("monitor.register", "監視フォルダを選択…")
        case .start: return UIM("monitor.start", "監視を開始")
        case .stop: return UIM("monitor.stop", "監視を停止")
        case .reviewRegistration: return UIM("monitor.registration_issue", "登録の問題を確認")
        case .reviewOtherRegistration: return UIM("monitor.register_other", "別の登録を確認")
        case .checkMonitor: return UIM("monitor.check_status", "監視状態を確認")
        }
    }
}

@MainActor func orchardRegistrationIssueAlert(_ reason: UIMessage, language: UILanguage) -> NSAlert {
    let alert = OrchardPearlArt.makeAlert()
    alert.messageText = OrchardMonitorAction.reviewRegistration.label.render(language)
    alert.informativeText = reason.render(language)
    alert.addButton(withTitle: UIM("ui.common.close", "閉じる").render(language))
    let recheck = alert.addButton(withTitle: UIM("monitor.register_again", "登録を再確認").render(language))
    recheck.keyEquivalent = ""
    return alert
}

@MainActor final class OrchardPearlHomeSurface: NSView {
    let monitorTitle = NSTextField(wrappingLabelWithString: "")
    let monitorDetails = NSTextField(wrappingLabelWithString: "")
    let monitorAction = NSButton(title: "", target: nil, action: nil)
    let reviewChanges = NSButton(title: "", target: nil, action: nil)
    let changeHistory = NSButton(title: "", target: nil, action: nil)
    let changeMonitorTarget = NSButton(title: "", target: nil, action: nil)
    let monitorMessage = NSTextField(wrappingLabelWithString: "")
    let language = OrchardPearlLanguageControl(labels: ["日本語", "English"], trackingMode: .selectOne, target: nil, action: nil)

    private let zip: OrchardZipHomeControls
    private let preference: UILanguagePreference
    private let languageChanged: () -> Void
    private let brand = NSTextField(labelWithString: "Orchard 🍎")
    private let build = NSTextField(wrappingLabelWithString: "")
    private let preferenceNotice = NSTextField(wrappingLabelWithString: "")
    private let monitorHeading = NSTextField(wrappingLabelWithString: "")
    private let monitorDescription = NSTextField(wrappingLabelWithString: "")
    private let monitorNote = NSTextField(wrappingLabelWithString: "")
    private let viewport = NSScrollView()
    private let document = OrchardZipResultCanvas()
    private let rim = OrchardPearlPerimeter()
    private let hero = OrchardZipResultCanvas()
    private let cards = NSStackView()
    private let monitorCard = OrchardZipResultCanvas()
    private let scopeCard = OrchardZipResultCanvas()
    private let archive = NSImageView()
    private var archiveWidth: NSLayoutConstraint!
    private var archiveHeight: NSLayoutConstraint!
    private var narrowCards: [NSLayoutConstraint] = []
    private var equalCardHeight: NSLayoutConstraint!
    private var compact: Bool?
    private let headerHeight: CGFloat = 78

    override var isFlipped: Bool { true }
    override var mouseDownCanMoveWindow: Bool { true }

    init(zip: OrchardZipHomeControls, preference: UILanguagePreference, languageChanged: @escaping () -> Void) {
        self.zip = zip
        self.preference = preference
        self.languageChanged = languageChanged
        super.init(frame: .zero)

        zip.onFrameChange = { [weak rim] tone in rim?.apply(tone, animated: tone != .pearl) }
        setAccessibilityIdentifier("orchard.home")
        brand.font = .systemFont(ofSize: 26, weight: .bold)
        brand.setAccessibilityIdentifier("orchard.home.brand")
        language.segmentStyle = .rounded
        language.setWidth(72, forSegment: 0)
        language.setWidth(72, forSegment: 1)
        language.target = self
        language.action = #selector(chooseLanguage)
        language.setAccessibilityIdentifier("orchard.ui.language")
        language.setAccessibilityLabel("Language / 言語")
        language.setAccessibilityHelp("日本語 / English")

        for field in [monitorHeading, monitorTitle, monitorDescription, monitorMessage, monitorDetails, monitorNote, build, preferenceNotice] {
            field.maximumNumberOfLines = 0
            field.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
            field.setContentCompressionResistancePriority(.required, for: .vertical)
        }
        monitorHeading.font = .systemFont(ofSize: 18, weight: .semibold)
        monitorTitle.font = .systemFont(ofSize: 16, weight: .semibold)
        monitorDescription.font = .systemFont(ofSize: 13)
        monitorDetails.font = .systemFont(ofSize: 13)
        monitorDetails.isSelectable = true
        monitorDetails.lineBreakMode = .byCharWrapping
        monitorDetails.setAccessibilityIdentifier("orchard.home.monitor.details")
        monitorMessage.font = .systemFont(ofSize: 13, weight: .medium)
        monitorMessage.lineBreakMode = .byCharWrapping
        monitorMessage.isHidden = true
        monitorNote.font = .systemFont(ofSize: 12)
        build.font = .systemFont(ofSize: 11)
        preferenceNotice.font = .systemFont(ofSize: 12, weight: .medium)
        for field in [monitorDescription, monitorNote, build, preferenceNotice] {
            field.textColor = .secondaryLabelColor
        }
        monitorTitle.setAccessibilityIdentifier("orchard.home.monitor.state")
        monitorAction.bezelStyle = .rounded
        reviewChanges.bezelStyle = .rounded
        changeHistory.bezelStyle = .rounded
        changeMonitorTarget.bezelStyle = .rounded
        monitorAction.setAccessibilityIdentifier("orchard.monitor.primary")
        reviewChanges.setAccessibilityIdentifier("orchard.monitor.review")
        changeHistory.setAccessibilityIdentifier("orchard.monitor.history")
        changeMonitorTarget.setAccessibilityIdentifier("orchard.monitor.change_target")
        reviewChanges.isEnabled = false
        changeHistory.isEnabled = false
        changeMonitorTarget.isHidden = true
        let monitorControls = NSStackView(views: [monitorAction, reviewChanges, changeHistory, changeMonitorTarget])
        monitorControls.orientation = .vertical
        monitorControls.alignment = .leading
        monitorControls.spacing = 5
        let monitorHeader = orchardHomeCardHeading(monitorHeading, symbol: "waveform.path", hue: 0x775486)
        let monitor = NSStackView(views: [monitorHeader, monitorDescription, monitorTitle, monitorDetails,
                                          monitorControls, monitorMessage, monitorNote])
        monitor.orientation = .vertical
        monitor.alignment = .leading
        monitor.spacing = 9
        monitor.setCustomSpacing(12, after: monitorDescription)
        monitor.setCustomSpacing(12, after: monitorDetails)
        for item in [monitorHeader, monitorDescription, monitorTitle, monitorDetails, monitorMessage, monitorNote] as [NSView] {
            item.widthAnchor.constraint(equalTo: monitor.widthAnchor).isActive = true
        }

        archive.image = OrchardPearlArt.archiveIcon(warning: false, showsBadge: false)
        archive.imageScaling = .scaleProportionallyUpOrDown
        archive.setAccessibilityElement(false)
        archive.translatesAutoresizingMaskIntoConstraints = false
        archiveWidth = archive.widthAnchor.constraint(equalToConstant: 124)
        archiveHeight = archive.heightAnchor.constraint(equalToConstant: 128)
        zip.hero.translatesAutoresizingMaskIntoConstraints = false
        hero.addSubview(archive)
        hero.addSubview(zip.hero)
        hero.setAccessibilityIdentifier("orchard.home.hero")
        hero.paint = { [weak self] _ in
            guard let self else { return }
            OrchardPearlArt.hero(in: self.hero.bounds, dividerX: self.archive.frame.maxX + 10,
                                  dividerEnd: self.hero.bounds.maxY - 20, warning: false,
                                  system: OrchardPearlArt.prefersAccessibleMaterials)
        }
        NSLayoutConstraint.activate([
            archive.leadingAnchor.constraint(equalTo: hero.leadingAnchor, constant: 18),
            archive.centerYAnchor.constraint(equalTo: hero.centerYAnchor),
            archiveWidth, archiveHeight,
            zip.hero.leadingAnchor.constraint(equalTo: archive.trailingAnchor, constant: 23),
            zip.hero.trailingAnchor.constraint(equalTo: hero.trailingAnchor, constant: -22),
            zip.hero.topAnchor.constraint(equalTo: hero.topAnchor, constant: 19),
            zip.hero.bottomAnchor.constraint(equalTo: hero.bottomAnchor, constant: -19),
            hero.heightAnchor.constraint(greaterThanOrEqualToConstant: 167)
        ])

        install(monitor, in: monitorCard, hue: 0xD2A8CF, id: "orchard.home.monitor")
        install(zip.scope, in: scopeCard, hue: 0xA4C6E5, id: "orchard.home.scope")
        cards.addArrangedSubview(monitorCard)
        cards.addArrangedSubview(scopeCard)
        cards.spacing = 16
        equalCardHeight = monitorCard.heightAnchor.constraint(equalTo: scopeCard.heightAnchor)
        narrowCards = [monitorCard.widthAnchor.constraint(equalTo: cards.widthAnchor),
                       scopeCard.widthAnchor.constraint(equalTo: cards.widthAnchor)]

        let contents = NSStackView(views: [preferenceNotice, hero, cards, build])
        contents.orientation = .vertical
        contents.alignment = .leading
        contents.spacing = 16
        contents.translatesAutoresizingMaskIntoConstraints = false
        document.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(contents)
        viewport.drawsBackground = false
        viewport.borderType = .noBorder
        viewport.hasVerticalScroller = true
        viewport.autohidesScrollers = true
        viewport.documentView = document
        viewport.setAccessibilityIdentifier("orchard.home.scroll")
        NSLayoutConstraint.activate([
            document.widthAnchor.constraint(equalTo: viewport.contentView.widthAnchor),
            contents.leadingAnchor.constraint(equalTo: document.leadingAnchor, constant: 17),
            contents.trailingAnchor.constraint(equalTo: document.trailingAnchor, constant: -17),
            contents.topAnchor.constraint(equalTo: document.topAnchor, constant: 15),
            contents.bottomAnchor.constraint(equalTo: document.bottomAnchor, constant: -14),
            preferenceNotice.widthAnchor.constraint(equalTo: contents.widthAnchor),
            hero.widthAnchor.constraint(equalTo: contents.widthAnchor),
            cards.widthAnchor.constraint(equalTo: contents.widthAnchor),
            build.widthAnchor.constraint(equalTo: contents.widthAnchor)
        ])
        for view in [rim, brand, language, viewport] { addSubview(view) }
        setAccessibilityChildren([brand, language, viewport])
        applyWidth()
        renderLanguage()
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(displayOptionsChanged),
            name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification, object: nil)
    }

    required init?(coder: NSCoder) { nil }

    func makeWindow() -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1000, height: 712),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        OrchardPearlArt.applyWindowFrame(to: window)
        window.title = "Orchard 🍎"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isMovableByWindowBackground = true
        window.contentMinSize = NSSize(width: 468, height: 544)
        window.isReleasedWhenClosed = false
        window.contentView = self
        window.initialFirstResponder = zip.choose
        window.center()
        return window
    }

    private func install(_ content: NSView, in panel: OrchardZipResultCanvas, hue: UInt32, id: String) {
        panel.paint = { [weak panel] _ in
            guard let panel else { return }
            OrchardPearlArt.informationCard(panel.bounds, hue: hue, system: OrchardPearlArt.prefersAccessibleMaterials)
        }
        panel.setAccessibilityIdentifier(id)
        content.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(content)
        let preferredBottom = content.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -17)
        preferredBottom.priority = NSLayoutConstraint.Priority(249)
        NSLayoutConstraint.activate([
            preferredBottom,
            content.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 19),
            content.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -19),
            content.topAnchor.constraint(equalTo: panel.topAnchor, constant: 17),
            content.bottomAnchor.constraint(lessThanOrEqualTo: panel.bottomAnchor, constant: -17)
        ])
    }

    private func applyWidth() {
        let narrow = bounds.width < 760
        guard narrow != compact else { return }
        compact = narrow
        NSLayoutConstraint.deactivate(narrowCards)
        equalCardHeight.isActive = false
        cards.orientation = narrow ? .vertical : .horizontal
        cards.alignment = narrow ? .leading : .top
        cards.distribution = narrow ? .fill : .fillEqually
        if narrow { NSLayoutConstraint.activate(narrowCards) }
        else { equalCardHeight.isActive = true }
        archiveWidth.constant = narrow ? 73 : 124
        archiveHeight.constant = narrow ? 92 : 128
        zip.setCompact(narrow)
    }

    override func layout() {
        super.layout()
        let x: CGFloat = bounds.width < 760 ? 25 : 27
        brand.frame = NSRect(x: x, y: 31, width: max(0, min(260, bounds.width - 203)), height: 34)
        language.frame = NSRect(x: max(x, bounds.width - x - 153), y: 30, width: 153, height: 34)
        viewport.frame = NSRect(x: 8, y: headerHeight, width: max(0, bounds.width - 16),
                                height: max(0, bounds.height - headerHeight - 8))
        rim.frame = bounds
        applyWidth()
        rim.setLighting(size: bounds.size, scale: window?.backingScaleFactor ?? 1)
    }

    override func draw(_ dirtyRect: NSRect) {
        OrchardPearlArt.frame(in: bounds, header: headerHeight, system: OrchardPearlArt.prefersAccessibleMaterials)
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
        needsLayout = true
        for panel in [hero, monitorCard, scopeCard] { panel.needsDisplay = true }
    }

    @objc private func displayOptionsChanged() {
        func invalidate(_ view: NSView) {
            view.needsDisplay = true
            for child in view.subviews { invalidate(child) }
        }
        invalidate(self)
    }

    override func viewDidChangeBackingProperties() {
        super.viewDidChangeBackingProperties()
        needsLayout = true
    }

    @objc private func chooseLanguage() {
        guard language.selectedSegment == 0 || language.selectedSegment == 1 else { return }
        preference.choose(language.selectedSegment == 0 ? .ja : .en)
        renderLanguage()
        languageChanged()
    }

    func renderLanguage() {
        let selected = preference.language
        func set(_ label: NSTextField, _ copy: UIMessage) {
            label.stringValue = copy.render(selected)
            label.setAccessibilityLabel(label.stringValue)
        }
        set(monitorHeading, UIM("monitor.title", "指示ファイルの監視"))
        set(monitorDescription, UIM("monitor.description", "選んだフォルダ内のAGENTS.mdなど5種類を監視します。変更時は日本語説明と差分を確認してから承認できます。"))
        set(monitorNote, UIM("monitor.detection_disclaimer", "変更検知は攻撃・危険性の判定ではありません。未確認の証拠は、停止やアプリ再起動で消えません。"))
        set(build, UIM("ui.header.build", "Orchard 0.4  ·  build12  ·  実SHA 300,000件  ·  自動更新なし  ·  ログイン時の常駐登録は無効"))
        set(preferenceNotice, UIM("ui.language.save_unverified", "この表示言語は今回有効ですが、再起動後の設定保持は確認できません。"))
        preferenceNotice.isHidden = preference.persistenceConfirmed
        language.selectedSegment = selected == .ja ? 0 : 1
        language.setAccessibilityValue(selected == .ja ? "日本語" : "English")
        language.needsDisplay = true
    }
}

@MainActor
private enum InstructionReviewModal {
    static func setSafeDefault(_ button: NSButton, in window: NSWindow) {
        window.initialFirstResponder = button
        window.defaultButtonCell = button.cell as? NSButtonCell
        button.keyEquivalent = "\r"
        button.keyEquivalentModifierMask = []
    }

    static func run(_ window: NSWindow, onReturn fallback: NSApplication.ModalResponse,
                    _ present: () -> NSApplication.ModalResponse) -> NSApplication.ModalResponse {
        let eventBeforeModal = NSApp.currentEvent
        var consumedReturn = false
        guard let monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown, handler: { event in
            let consumed = MainActor.assumeIsolated {
                guard NSApp.modalWindow === window, isReturnPress(event) else { return false }
                consumedReturn = true
                NSApp.stopModal(withCode: fallback)
                return true
            }
            return consumed ? nil : event
        }) else { return fallback }
        defer { NSEvent.removeMonitor(monitor) }

        let outcome = present()
        // Keep Return non-committing even if a responder handles it inside AppKit.
        if consumedReturn { return fallback }
        if let event = NSApp.currentEvent, event !== eventBeforeModal, isReturnPress(event) {
            return fallback
        }
        return outcome
    }

    static func confirms(_ alert: NSAlert, cancel: NSButton) -> Bool {
        let window = alert.window
        setSafeDefault(cancel, in: window)
        return run(window, onReturn: .alertSecondButtonReturn) {
            alert.runModal()
        } == .alertFirstButtonReturn
    }

    private static func isReturnPress(_ event: NSEvent) -> Bool {
        guard event.type == .keyDown else { return false }
        if event.keyCode == 36 || event.keyCode == 76 { return true }
        return ["\r", "\n", "\u{3}"].contains(event.charactersIgnoringModifiers ?? "")
    }
}

@MainActor
private final class InstructionDecisionWindow: NSPanel {
    override func cancelOperation(_ sender: Any?) {
        performClose(sender)
    }
}

@MainActor
final class InstructionDecisionPanel: NSObject, NSWindowDelegate {
    enum Action: Int { case hold, approve, details, dismiss }

    let window: NSPanel
    private var result: Action = .hold
    private var runningModal = false

    init(path: String, filename: String, change: String, summary: InstructionChangeSummary,
         canApprove: Bool, canDismiss: Bool, blockedReason: String, japanese: Bool,
         width: CGFloat? = nil, brandIcon: NSImage? = nil) {
        let available = NSScreen.main?.visibleFrame.size ?? NSSize(width: 900, height: 750)
        let size = width ?? min(638, max(380, available.width - 36))
        let surface = InstructionDecisionSurface(width: size, path: path, filename: filename,
            change: change, summary: summary, canApprove: canApprove, canDismiss: canDismiss,
            blockedReason: blockedReason, japanese: japanese,
            brandIcon: brandIcon ?? NSApp.applicationIconImage)
        window = InstructionDecisionWindow(contentRect: NSRect(x: 0, y: 0, width: size,
            height: min(surface.preferredHeight, max(330, available.height - 30))),
            styleMask: [.titled, .closable, .fullSizeContentView], backing: .buffered, defer: false)
        super.init()

        OrchardPearlArt.applyWindowFrame(to: window)
        window.title = japanese ? "指示の変更を確認" : "Review instruction change"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.isReleasedWhenClosed = false
        window.delegate = self
        window.contentView = surface
        InstructionReviewModal.setSafeDefault(surface.hold, in: window)
        for (index, button) in surface.buttons.enumerated() {
            button.target = self
            button.action = #selector(choose(_:))
            button.nextKeyView = surface.buttons[(index + 1) % surface.buttons.count]
        }
    }

    func runModal() -> Action {
        result = .hold
        runningModal = true
        window.center()
        window.makeKeyAndOrderFront(nil)
        let response = InstructionReviewModal.run(window, onReturn: .abort) {
            NSApp.runModal(for: window)
        }
        runningModal = false
        window.orderOut(nil)
        return response == .abort ? .hold : result
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard runningModal else { return true }
        finish(.hold)
        return false
    }

    @objc private func choose(_ sender: NSButton) {
        guard runningModal, let action = Action(rawValue: sender.tag) else { return }
        finish(action)
    }

    private func finish(_ action: Action) {
        result = action
        NSApp.stopModal()
    }
}

@MainActor
private final class InstructionDecisionSurface: NSView {
    let hold: OrchardPearlButton
    let buttons: [NSButton]
    let preferredHeight: CGFloat
    private let rim = OrchardPearlPerimeter()
    private let brand = NSTextField(labelWithString: "Orchard")
    private let brandImage = NSImageView()
    private let viewport = NSScrollView()
    private let document = OrchardZipResultCanvas()
    private let body: NSStackView
    private let decisions: NSStackView
    private static let header: CGFloat = 62
    private static let inset: CGFloat = 18
    private static let gap: CGFloat = 12

    override var isFlipped: Bool { true }

    init(width: CGFloat, path: String, filename: String, change: String, summary: InstructionChangeSummary,
         canApprove: Bool, canDismiss: Bool, blockedReason: String, japanese: Bool, brandIcon: NSImage) {
        func text(_ ja: String, _ en: String) -> String { japanese ? ja : en }
        let contentWidth = width - 2 * Self.inset
        let main = Self.action(text("保留して戻る", "Keep pending"), role: .primary, action: .hold)
        hold = main
        var primary: [NSButton] = [main]
        if canApprove {
            primary.append(Self.action(text("監視基準への反映を確認", "Review baseline approval"),
                                       role: .secondary, action: .approve))
        }
        var secondary = [Self.utility(text("原文と差分を開く", "Open text and diff"), action: .details)]
        if canDismiss {
            secondary.append(Self.utility(text("未承認のまま通知を閉じる", "Dismiss without approval"), action: .dismiss))
        }
        buttons = primary + secondary

        let hero = Self.impactCard(summary, reason: blockedReason, japanese: japanese, width: contentWidth)
        let changed = Self.changeCard(path: path, filename: filename, change: change, summary: summary,
                                      japanese: japanese, width: contentWidth)
        let bodyStack = Self.column([hero, changed], width: contentWidth, spacing: Self.gap)
        body = bodyStack
        let actionTitle = canApprove ? text("監視基準に反映しますか", "Accept into the monitoring baseline?")
                                     : text("比較できるまで保留", "Keep pending until comparison is available")
        let decisionScope = canApprove ? text("承認の対象は監視基準です。AIへの実行許可は別に判断してください。",
                                              "Approval updates the monitoring baseline. Decide execution permissions separately.")
                                       : text("原文と差分から比較できる範囲を確認できます。",
                                              "Open text and diff to see what can be compared.")
        let primaryRow = Self.row(primary, width: contentWidth, height: 46, spacing: 10)
        let utilities = Self.row(secondary, width: contentWidth, height: 28, spacing: 8)
        let decisionStack = Self.column([
            Self.label(actionTitle, width: contentWidth, size: 18, weight: .semibold, id: "decision.heading"),
            Self.label(decisionScope, width: contentWidth, size: 13, id: "decision.scope"),
            primaryRow,
            utilities
        ], width: contentWidth, spacing: 6)
        decisions = decisionStack
        preferredHeight = Self.header + 3 * Self.gap + bodyStack.frame.height + decisionStack.frame.height
        super.init(frame: NSRect(x: 0, y: 0, width: width, height: preferredHeight))

        setAccessibilityIdentifier("orchard.monitor.decision.pearl")
        brand.font = .systemFont(ofSize: 21, weight: .bold)
        brand.setAccessibilityIdentifier("orchard.monitor.decision.brand")
        brandImage.image = brandIcon
        brandImage.imageScaling = .scaleProportionallyUpOrDown
        brandImage.setAccessibilityElement(false)
        viewport.drawsBackground = false
        viewport.borderType = .noBorder
        viewport.scrollerStyle = .overlay
        viewport.autohidesScrollers = true
        document.frame = body.frame
        document.addSubview(body)
        viewport.documentView = document
        for view in [brandImage, brand, viewport, decisions, rim] { addSubview(view) }
        setAccessibilityChildren([brand, viewport, decisions])
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(displayOptionsChanged),
            name: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification, object: nil)
    }

    required init?(coder: NSCoder) { nil }

    override func layout() {
        super.layout()
        brandImage.frame = NSRect(x: 20, y: 26, width: 32, height: 32)
        brand.frame = NSRect(x: 59, y: 28, width: 150, height: 28)
        decisions.frame.origin = NSPoint(x: Self.inset, y: bounds.height - Self.gap - decisions.frame.height)
        let bodyTop = Self.header + Self.gap
        let bodyHeight = max(0, decisions.frame.minY - Self.gap - bodyTop)
        viewport.frame = NSRect(x: Self.inset, y: bodyTop, width: body.frame.width, height: bodyHeight)
        viewport.hasVerticalScroller = body.frame.height > bodyHeight + 1
        rim.frame = bounds
        rim.setLighting(size: bounds.size, scale: window?.backingScaleFactor ?? 1)
    }

    override func draw(_ dirtyRect: NSRect) {
        OrchardPearlArt.frame(in: bounds, header: Self.header, system: OrchardPearlArt.prefersAccessibleMaterials)
    }

    override func viewDidChangeBackingProperties() {
        super.viewDidChangeBackingProperties()
        needsLayout = true
    }

    @objc private func displayOptionsChanged() {
        func invalidate(_ view: NSView) {
            view.needsDisplay = true
            for child in view.subviews { invalidate(child) }
        }
        invalidate(self)
    }

    private static func impactCard(_ summary: InstructionChangeSummary, reason: String,
                                   japanese: Bool, width: CGFloat) -> OrchardZipResultCanvas {
        let padding: CGFloat = 17
        let separated = width >= 460 || summary.level != nil
        let leftWidth = separated ? (summary.level == nil ? 218 : 136) : width - 2 * padding
        let rightWidth = separated ? width - leftWidth - 2 * padding - 24 : leftWidth
        let limited = summary.levelLimited
        let caption = japanese ? (limited ? "確認範囲の影響レベル" : "影響レベル")
                               : (limited ? "Observed impact level" : "Impact level")
        let value = summary.level.map { "\($0) / 5" } ?? (japanese ? "判定不能" : "Undetermined")
        let heading = label(caption, width: leftWidth, size: 12.5, weight: .semibold, id: "impact.caption")
        let score = label(value, width: leftWidth, size: summary.level == nil ? 27 : 36, weight: .bold, id: "impact.level")
        score.setAccessibilityLabel(caption + " " + value)
        if summary.highImpact {
            let ink = NSColor(srgbRed: 0.53, green: 0.09, blue: 0.2, alpha: 1)
            score.textColor = ink
        }
        let severity = column([heading, score], width: leftWidth, spacing: 2)
        let impact = reason.isEmpty || summary.highImpact ? summary.impact : reason
        var notes = summary.notes
        if summary.highImpact && !reason.isEmpty { notes.append(reason) }
        if impact == reason { notes = [] }
        let title = label(impact, width: rightWidth, size: 18, weight: .semibold, id: "impact.action")
        var fields: [NSView] = [title]
        if !notes.isEmpty {
            fields.append(label(notes.joined(separator: " "), width: rightWidth, size: 13, id: "impact.context"))
        }
        fields.append(label(japanese ? "実際の権限・実行は未確認" : "Actual permissions and execution are unverified",
                            width: rightWidth, size: 13, id: "impact.authority"))
        let evidence = column(fields, width: rightWidth, spacing: 5)
        let height = (separated ? max(severity.frame.height, evidence.frame.height)
                                : severity.frame.height + evidence.frame.height + 7) + 2 * padding
        let panel = canvas(width, height, id: "impact.hero")
        severity.frame.origin = NSPoint(x: padding, y: separated ? (height - severity.frame.height) / 2 : padding)
        evidence.frame.origin = separated ? NSPoint(x: width - padding - rightWidth, y: (height - evidence.frame.height) / 2)
                                          : NSPoint(x: padding, y: severity.frame.maxY + 7)
        panel.addSubview(severity)
        panel.addSubview(evidence)
        let divider = padding + leftWidth + 12
        panel.paint = { [weak panel] _ in
            guard let panel else { return }
            let accessible = OrchardPearlArt.prefersAccessibleMaterials
            if separated {
                OrchardPearlArt.hero(in: panel.bounds, dividerX: divider, dividerEnd: panel.bounds.maxY - 20,
                                     warning: summary.highImpact, system: accessible)
            } else {
                OrchardPearlArt.informationCard(panel.bounds, hue: 0xD2A8CF, system: accessible)
            }
        }
        return panel
    }

    private static func changeCard(path: String, filename: String, change: String, summary: InstructionChangeSummary,
                                   japanese: Bool, width: CGFloat) -> OrchardZipResultCanvas {
        let padding: CGFloat = 17
        let lineWidth = width - 2 * padding
        let headline = label(japanese ? "変更の要点" : "What changed", width: lineWidth,
                             size: 13, weight: .semibold, id: "change.heading")
        let name = label((filename.isEmpty ? path : filename) + "  ·  " + change, width: lineWidth,
                         size: 20, weight: .semibold, id: "change.file", singleLine: true)
        name.toolTip = path
        name.setAccessibilityHelp(path)
        let changes = summary.changes.enumerated().map { index, change in
            label(change, width: lineWidth, size: 14, id: "change.line.\(index)")
        }
        let content = column([headline, name] + changes, width: lineWidth, spacing: 6)
        let panel = canvas(width, content.frame.height + 24, id: "change.card")
        content.frame.origin = NSPoint(x: padding, y: 12)
        panel.addSubview(content)
        panel.paint = { [weak panel] _ in
            guard let panel else { return }
            OrchardPearlArt.informationCard(panel.bounds, hue: 0xD2A8CF,
                                           system: OrchardPearlArt.prefersAccessibleMaterials)
        }
        return panel
    }

    private static func canvas(_ width: CGFloat, _ height: CGFloat, id: String) -> OrchardZipResultCanvas {
        let panel = OrchardZipResultCanvas(frame: NSRect(x: 0, y: 0, width: width, height: height))
        panel.setAccessibilityIdentifier("orchard.monitor.decision." + id)
        panel.heightAnchor.constraint(equalToConstant: height).isActive = true
        return panel
    }

    private static func column(_ views: [NSView], width: CGFloat, spacing: CGFloat) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = spacing
        for view in views { view.widthAnchor.constraint(equalToConstant: width).isActive = true }
        stack.frame.size = NSSize(width: width, height: ceil(stack.fittingSize.height))
        return stack
    }

    private static func row(_ buttons: [NSButton], width: CGFloat, height: CGFloat, spacing: CGFloat) -> NSStackView {
        let equalWidth = (width - spacing * CGFloat(buttons.count - 1)) / CGFloat(buttons.count)
        let vertical = buttons.contains { button in
            let title = NSAttributedString(string: button.title, attributes: [.font: button.font ?? NSFont.systemFont(ofSize: 14)])
            return title.size().width + 30 > equalWidth
        }
        let stack = NSStackView(views: buttons)
        stack.orientation = vertical ? .vertical : .horizontal
        stack.alignment = vertical ? .leading : .centerY
        stack.spacing = spacing
        for button in buttons {
            button.widthAnchor.constraint(equalToConstant: vertical ? width : equalWidth).isActive = true
            button.heightAnchor.constraint(equalToConstant: height).isActive = true
        }
        stack.heightAnchor.constraint(equalToConstant: vertical ? height * CGFloat(buttons.count) +
                                      spacing * CGFloat(buttons.count - 1) : height).isActive = true
        return stack
    }

    private static func label(_ value: String, width: CGFloat, size: CGFloat, weight: NSFont.Weight = .regular,
                              id: String, singleLine: Bool = false) -> NSTextField {
        let field = singleLine ? NSTextField(labelWithString: value) : NSTextField(wrappingLabelWithString: value)
        if singleLine {
            field.lineBreakMode = .byTruncatingMiddle
            field.maximumNumberOfLines = 1
        }
        field.font = .systemFont(ofSize: size, weight: weight)
        field.preferredMaxLayoutWidth = width
        field.setContentCompressionResistancePriority(.required, for: .vertical)
        field.setAccessibilityIdentifier("orchard.monitor.decision." + id)
        return field
    }

    private static func action(_ title: String, role: OrchardPearlButton.AppearanceRole,
                               action: InstructionDecisionPanel.Action) -> OrchardPearlButton {
        let button = OrchardPearlButton(title: title, target: nil, action: nil)
        button.appearanceRole = role
        button.font = .systemFont(ofSize: 14, weight: .semibold)
        button.bezelStyle = .rounded
        identify(button, action: action)
        return button
    }

    private static func utility(_ title: String, action: InstructionDecisionPanel.Action) -> NSButton {
        let button = NSButton(title: title, target: nil, action: nil)
        button.isBordered = false
        let font = NSFont.systemFont(ofSize: 13.5, weight: .medium)
        button.font = font
        button.attributedTitle = NSAttributedString(string: title, attributes: [
            .font: font, .foregroundColor: NSColor.labelColor, .underlineStyle: NSUnderlineStyle.single.rawValue
        ])
        identify(button, action: action)
        return button
    }

    private static func identify(_ button: NSButton, action: InstructionDecisionPanel.Action) {
        button.tag = action.rawValue
        button.setAccessibilityLabel(button.title)
        button.setAccessibilityIdentifier("orchard.monitor.decision." + String(describing: action))
        button.focusRingType = .exterior
    }
}

@MainActor
private final class MenuController: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
    private var alertBindings: UIBindingSet?
    private var homeSurface: OrchardPearlHomeSurface?
    private var actionMessage: UIMessage?
    private var presentationSnapshot: MonitorPresentationSnapshot?
    private let options: Options
    private var selectedRoot: String
    private var selectedStateDir: String
    private var registrationError: String?
    private var registrationIntake: RegistrationIntake?
    private var previewReviewButton: NSButton?
    private var monitorResponse: [String: Any]?
    private var displayedState: DisplayState = .unregistered
    private var ownedWatcher: Process?
    private var startingWatcher = false
    private var targetSwitchInFlight = false
    private var item: NSStatusItem?
    private var timer: Timer?
    private let zipController = OrchardZipController()
    private var preview: NSWindow?
    private var previewTitle: NSTextField?
    private var previewDetails: NSTextField?
    private var previewMenuEvidence: NSTextField?
    private var previewActionResult: NSTextField?
    private var previewMonitorButton: NSButton?
    private var noticeCache: NoticeSnapshotCache?
    private var noticeInteractionInFlight = false
    private var displayedTitle: String?
    private var displayedLines: [String] = []
    private var displayedNoticeIDs: [String] = []
    private var displayedRoot: String?
    private var alertPanel: NSPanel?
    private var alertRow: ChangeRow?
    private var completedAlertClaims = Set<String>()
    private var lastAlertClaimAttempt: [String: TimeInterval] = [:]
    private let loginService = SentinelLoginService()
    private var residencyMutationInFlight = false
    private var automaticWatcher = false
    private var automaticStopRequested = false
    private var recoverySuppressed = false
    private var nextRecoveryProbe = Date.distantPast

    init(options: Options) {
        self.options = options
        selectedRoot = options.root
        selectedStateDir = options.stateDir
        registrationError = options.registrationError
        registrationIntake = options.registrationIntake
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        installOrchardMenu()
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        makePreviewWindow()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: options.interval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        zipController.cancelForTermination()
        if let ownedWatcher, ownedWatcher.isRunning { ownedWatcher.interrupt() }
    }

    private func installOrchardMenu() {
        let bar = NSMenu()
        let appItem = NSMenuItem()
        let menu = NSMenu(title: "Orchard")
        menu.addItem(withTitle: UIL("ui.menu.open", "Orchardを開く"), action: #selector(reopenOrchard), keyEquivalent: "0").target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: UIL("ui.menu.quit", "Orchardを終了"), action: #selector(quitApp), keyEquivalent: "q").target = self
        appItem.submenu = menu
        bar.addItem(appItem)
        let editItem = NSMenuItem()
        let edit = NSMenu(title: UIL("ui.menu.edit", "編集"))
        edit.addItem(withTitle: UIL("ui.menu.copy", "コピー"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: UIL("ui.menu.select_all", "すべて選択"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        editItem.submenu = edit
        bar.addItem(editItem)
        NSApp.mainMenu = bar
    }

    @objc private func reopenOrchard() {
        preview?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        reopenOrchard()
        return true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if zipController.deferTermination({ clean in sender.reply(toApplicationShouldTerminate: clean) }) {
            return .terminateLater
        }
        return .terminateNow
    }

    private func makePreviewWindow() {
        let surface = OrchardPearlHomeSurface(zip: zipController.home, preference: .shared) { [weak self] in
            self?.renderLanguage()
        }
        surface.monitorAction.target = self
        surface.monitorAction.action = #selector(primaryMonitorAction)
        surface.reviewChanges.target = self
        surface.reviewChanges.action = #selector(reviewFirstPending)
        surface.changeHistory.target = self
        surface.changeHistory.action = #selector(openMDHistory)
        surface.changeMonitorTarget.target = self
        surface.changeMonitorTarget.action = #selector(changeMonitoredFolder)
        previewTitle = surface.monitorTitle
        previewDetails = surface.monitorDetails
        previewActionResult = surface.monitorMessage
        previewMonitorButton = surface.monitorAction
        previewReviewButton = surface.reviewChanges
        homeSurface = surface
        zipController.onLanguageChange = { [weak self] in self?.renderLanguage() }

        let window = surface.makeWindow()
        preview = window
        setActionMessage(registrationIntake?.presentationNotice ?? .verbatim(""))
        renderLanguage()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func refresh(forceNoticeRead: Bool = false) {
        let registered = !selectedRoot.isEmpty && !selectedStateDir.isEmpty &&
            FileManager.default.fileExists(atPath: selectedStateDir + "/baseline.json")
        monitorResponse = registered ? nativeMonitorStatus(root: selectedRoot,
                                                           stateDir: selectedStateDir) : nil
        var presentationReason: UIMessage?
        var state = loadDisplayState(root: selectedRoot, stateDir: selectedStateDir,
                                     registrationError: registrationError,
                                     monitor: monitorResponse, registrationIssue: registrationIntake?.presentationMessage,
                                     presentation: { presentationReason = $0 }) {
            pendingSnapshot(forceRead: forceNoticeRead)
        }
        if startingWatcher, case .stopped(let rows) = state,
           let ownedWatcher, ownedWatcher.isRunning {
            state = .unknown(rows, "監視プロセスの起動を確認中")
            presentationReason = UIM("monitor.starting", "監視プロセスの起動を確認中")
        }
        if state.isRunning, let pid = monitorResponse?["pid"] as? Int,
           ownedWatcher?.isRunning != true || Int(ownedWatcher?.processIdentifier ?? -1) != pid {
            state = .unknown(state.rows, "[登録確認] 旧版または別のOrchardが監視中です。そちらで停止して終了後、登録を再確認してください。二重監視は開始しません。")
            presentationReason = UIM("monitor.reason.other_active", "[登録確認] 旧版または別のOrchardが監視中です。そちらで停止して終了後、登録を再確認してください。二重監視は開始しません。")
        }
        if startingWatcher {
            if state.isRunning {
                startingWatcher = false
                setActionMessage(UIM("monitor.running.notice", "監視中です。指示ファイルの変更を検知したら通知します。"))
            } else if ownedWatcher?.isRunning == false {
                startingWatcher = false
                setActionMessage(UIM("monitor.start_failed", "監視プロセスを起動できませんでした。未確認証拠は保持しています。"))
            }
        }
        displayedState = state
        let activeIDs = Set(state.activeRows.map(\.id))
        completedAlertClaims.formIntersection(activeIDs)
        lastAlertClaimAttempt = lastAlertClaimAttempt.filter { activeIDs.contains($0.key) }
        if let active = alertRow, !activeIDs.contains(active.id) {
            alertPanel?.close()
        }
        if !state.isRunning { alertPanel?.close() }
        let osRegistration = loginService.status
        let policy = sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)
        reconcileResidency(state: state, registration: osRegistration, policy: policy)
        let action: OrchardMonitorAction
        switch state {
        case .unregistered: action = .chooseFolder
        case .running: action = .stop
        case .stopped: action = .start
        case .unknown(_, let reason):
            if registrationIntake?.status == "CHOICE" { action = .reviewOtherRegistration }
            else { action = reason.hasPrefix("[登録確認]") ? .reviewRegistration : .checkMonitor }
        }
        presentationSnapshot = MonitorPresentationSnapshot(state: state, reason: presentationReason,
            osRegistration: osRegistration, policy: policy, root: selectedRoot,
            registrationError: registrationError, action: action,
            runtimeError: options.runtimeError, manualRuntime: options.runtimeManifestSHA256 == nil)
        renderMonitorPresentation()
        if state.isRunning && alertPanel == nil && !targetSwitchInFlight && !noticeInteractionInFlight {
            showOneStableAlertIfNeeded()
        }
    }

    private func pendingSnapshot(forceRead: Bool) -> Result<[ChangeRow], NoticeReadFailure> {
        let stamps = noticeFileStamps(selectedStateDir)
        if !forceRead, let cached = noticeCache, let stamps,
           cached.root == selectedRoot, cached.stateDir == selectedStateDir, cached.stamps == stamps {
            return .success(cached.rows)
        }
        let result = readNoticeRows(options: options, root: selectedRoot, stateDir: selectedStateDir)
        if case .success(let rows) = result, let stamps, stamps == noticeFileStamps(selectedStateDir) {
            noticeCache = NoticeSnapshotCache(root: selectedRoot, stateDir: selectedStateDir, stamps: stamps, rows: rows)
        } else {
            noticeCache = nil
        }
        return result
    }

    private func renderMonitorPresentation() {
        guard let snapshot = presentationSnapshot else { return }
        let state = snapshot.state
        let reviewRows = state.activeRows
        let osRegistration = snapshot.osRegistration
        let policy = snapshot.policy
        let environment: UIMessage = snapshot.runtimeError != nil
            ? UIM("runtime.invalid", "同梱runtimeの同一性を確認できません。パッケージでは外部Pythonへの差し替えを許可しません。")
            : (snapshot.manualRuntime ? UIM("runtime.debug", "手動debug指定（同梱identity未検証）") : UIM("runtime.verified", "起動時の同梱runtime同一性を確認済み（発行者の信頼証明は別）"))
        let residencyLines = [
            UIM("runtime.line", "実行環境: {p0}", ["p0": UIValue(environment)]).text,
            UIM("residency.os_line", "ログイン項目（macOS）: {p0}", ["p0": UIValue(osRegistration.presentationMessage)]).text,
            UIM("residency.login_choice", "常駐の選択（保存希望）: {p0}", ["p0": UIValue(policy.map { $0.desiredLogin ? UIM("ui.value.on", "オン") : UIM("ui.value.off", "オフ") } ?? UIM("ui.common.not_verified", "未確認"))]).text,
            UIM("residency.monitor_choice", "自動監視の希望: {p0}", ["p0": UIValue(policy.map { $0.desiredMonitor ? UIM("ui.value.on", "オン") : UIM("ui.value.stopped", "停止") } ?? UIM("ui.common.not_verified", "未確認"))]).text,
            UIM("residency.reason_line", "自動監視の理由: {p0}", ["p0": UIValue(policy?.presentationReason ?? UIM("registration.unreadable", "保存状態を確認できません"))]).text,
            UIL("residency.login_status", "ログイン時の自動起動: この版では無効")]
        let visibleLines = localizedLines(for: state, reasonMessage: snapshot.reason)
        let currentLines = visibleLines + residencyLines
        previewMonitorButton?.title = snapshot.action.label.text
        previewMonitorButton?.isEnabled = !targetSwitchInFlight
        previewReviewButton?.isEnabled = !targetSwitchInFlight && !state.rows.isEmpty
        previewMonitorButton?.setAccessibilityLabel(previewMonitorButton?.title)
        previewReviewButton?.title = UIL("monitor.review_pending", "未確認の変更を確認")
        previewReviewButton?.setAccessibilityLabel(previewReviewButton?.title)
        homeSurface?.changeHistory.title = UIL("monitor.history.open", "変更履歴")
        homeSurface?.changeHistory.setAccessibilityLabel(homeSurface?.changeHistory.title)
        homeSurface?.changeHistory.isEnabled = !targetSwitchInFlight && !snapshot.root.isEmpty
        if let change = homeSurface?.changeMonitorTarget {
            change.title = UIL("registration.switch.action", "監視先を変更")
            change.isHidden = snapshot.root.isEmpty
            change.isEnabled = state.permitsReview && registrationIntake?.status == "READY" && !targetSwitchInFlight
            change.setAccessibilityLabel(change.title)
        }
        let title = localizedTitle(state)
        let noticeIDs = reviewRows.map(\.id)
        guard title != displayedTitle || currentLines != displayedLines
                || noticeIDs != displayedNoticeIDs || snapshot.root != displayedRoot else { return }
        displayedTitle = title; displayedLines = currentLines
        displayedNoticeIDs = noticeIDs
        displayedRoot = snapshot.root
        item?.button?.title = title
        item?.button?.toolTip = "Orchard — " + (currentLines.first ?? "")
        item?.button?.setAccessibilityLabel(title)
        item?.button?.setAccessibilityValue(currentLines.joined(separator: "\n"))
        previewTitle?.stringValue = title
        previewTitle?.setAccessibilityLabel(title)
        let folder = snapshot.root.isEmpty ? (snapshot.registrationError == nil ? UIL("monitor.root.none", "監視フォルダ: 未登録") : UIL("monitor.root.check", "監視フォルダ: 登録情報の確認待ち")) : UIM("monitor.root", "監視フォルダ: {p0}", ["p0": UIValue(safeLabel(snapshot.root))]).text
        previewDetails?.stringValue = ([folder] + visibleLines + [UIL("residency.login_detail", "ログイン時の常駐: この版では無効")]).joined(separator: "\n")
        previewDetails?.setAccessibilityLabel(previewDetails?.stringValue)
        let menu = NSMenu(title: "Orchard")
        menu.delegate = self
        for (index, line) in currentLines.enumerated() {
            let entry = NSMenuItem(title: line, action: nil, keyEquivalent: "")
            if index > 0 && index <= reviewRows.count {
                entry.action = #selector(reviewItem(_:))
                entry.target = self
                entry.representedObject = reviewRows[index - 1].id
            } else {
                entry.isEnabled = false
            }
            menu.addItem(entry)
        }
        menu.addItem(.separator())
        let control = NSMenuItem(title: snapshot.action.label.text, action: #selector(primaryMonitorAction), keyEquivalent: "")
        control.target = self
        menu.addItem(control)
        let history = NSMenuItem(title: UIL("monitor.history.open", "変更履歴"), action: #selector(openMDHistory), keyEquivalent: "")
        history.target = self
        if !snapshot.root.isEmpty { menu.addItem(history) }
        menu.addItem(.separator())
        let enableLogin = NSMenuItem(title: UIL("residency.menu.enable", "ログイン時の監視を有効にする…"), action: #selector(enableResidency), keyEquivalent: "")
        enableLogin.target = self
        enableLogin.isEnabled = false // No registration in this private integration build.
        menu.addItem(enableLogin)
        let disableLogin = NSMenuItem(title: UIL("residency.menu.disable", "ログイン登録を解除し、監視を停止する…"), action: #selector(disableResidency), keyEquivalent: "")
        disableLogin.target = self
        disableLogin.isEnabled = false
        menu.addItem(disableLogin)
        menu.addItem(.separator())
        let reopen = NSMenuItem(title: UIL("ui.menu.open", "Orchardを開く"), action: #selector(reopenOrchard), keyEquivalent: "")
        reopen.target = self
        menu.addItem(reopen)
        let quit = NSMenuItem(title: UIL("ui.menu.quit", "Orchardを終了"), action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        item?.menu = menu
    }
    private func renderLanguage() {
        // Pure redraw only: preserve first responder, selected ZIP, pending modal,
        // process ownership, monitor state and action eligibility.
        homeSurface?.renderLanguage()
        zipController.renderLanguage()
        alertBindings?.render()
        alertPanel?.title = UIL("monitor.panel_title", "Orchard Sentinel — 変更を検知")
        installOrchardMenu()
        previewActionResult?.stringValue = actionMessage?.text ?? ""
        previewActionResult?.setAccessibilityLabel(previewActionResult?.stringValue)
        previewActionResult?.isHidden = previewActionResult?.stringValue.isEmpty != false
        displayedTitle = nil
        renderMonitorPresentation()
    }
    private func setActionMessage(_ message: UIMessage) {
        actionMessage = message
        previewActionResult?.stringValue = message.text
        previewActionResult?.setAccessibilityLabel(message.text)
        previewActionResult?.isHidden = message.text.isEmpty
    }


    private func showOneStableAlertIfNeeded() {
        let now = Date().timeIntervalSince1970
        for row in displayedState.activeRows where now - row.lastActivityEpoch >= options.panelDebounce {
            let identity = row.id
            if completedAlertClaims.contains(identity) { continue }
            if let last = lastAlertClaimAttempt[identity], now - last < 5 { continue }
            lastAlertClaimAttempt[identity] = now
            let (status, response, _) = callDetector("claim-alert", arguments: ["--notice-id", identity])
            guard status == 0 else { continue }
            completedAlertClaims.insert(identity)
            guard (response?["claimed"] as? Bool) == true else { continue }
            showAlertPanel(for: row)
            return
        }
    }

    private func showAlertPanel(for row: ChangeRow) {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 240),
            styleMask: [.titled, .closable], backing: .buffered, defer: false
        )
        OrchardPearlArt.applyAppearance(to: panel)
        panel.title = UIL("monitor.panel_title", "Orchard Sentinel — 変更を検知")
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.level = .floating
        panel.delegate = self
        panel.center()
        let heading = NSTextField(labelWithString: UIL("monitor.detected.alert", "指示ファイルの変更を検知しました"))
        heading.font = .boldSystemFont(ofSize: 16)
        let detailMessage = UIM("monitor.panel_detail",
            "ファイル: {p0}\n検出: {p1}\n種類: {p2}\n\n通知を閉じても、ファイルの変更はそのまま残ります。",
            ["p0": UIValue(row.path), "p1": UIValue(localizedTimestamp(row.detectedAt)), "p2": UIValue(kindLabel(row.kind))])
        let detail = NSTextField(wrappingLabelWithString: detailMessage.text)
        detail.font = .systemFont(ofSize: 13)
        detail.preferredMaxLayoutWidth = 440
        let review = NSButton(title: UIL("monitor.detected.review", "変更内容を確認"), target: self, action: #selector(reviewFromPanel))
        let closeMessage = UIM("monitor.dismiss_notice", "通知だけ閉じる")
        let later = NSButton(title: closeMessage.text, target: self, action: #selector(dismissPanel))
        let buttons = NSStackView(views: [review, later])
        buttons.orientation = .horizontal
        buttons.spacing = 12
        let stack = NSStackView(views: [heading, detail, buttons])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView?.addSubview(stack)
        if let contentView = panel.contentView {
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 20),
                stack.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -20),
                stack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 18),
            ])
        }
        let panelBindings = UIBindingSet()
        panelBindings.text(heading, UIM("monitor.detected.alert", "指示ファイルの変更を検知しました"))
        panelBindings.text(detail, detailMessage)
        panelBindings.button(review, UIM("monitor.detected.review", "変更内容を確認"))
        panelBindings.button(later, closeMessage)
        alertBindings = panelBindings
        alertPanel = panel
        alertRow = row
        panel.orderFrontRegardless() // intentionally non-modal
    }

    private func kindLabel(_ kind: String) -> UIMessage {
        switch kind {
        case "ADDED": return UIM("monitor.kind.added", "追加")
        case "DELETED": return UIM("monitor.kind.deleted", "削除")
        case "CHANGED": return UIM("monitor.kind.changed", "変更")
        case "UNINSPECTABLE": return UIM("monitor.kind.uninspectable", "比較できない状態")
        default: return UIM("monitor.kind.other", "状態変更")
        }
    }

    @objc private func dismissPanel() {
        guard let row = alertRow else { return }
        let root = selectedRoot, stateDir = selectedStateDir
        withNoticeInteraction {
            _ = confirmNoticeDismissal(row, highImpact: false, root: root, stateDir: stateDir)
        }
    }

    @objc private func reviewFromPanel() {
        guard let row = alertRow else { return }
        withNoticeInteraction { reviewNotice(row) }
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        guard sender === alertPanel else { return true }
        dismissPanel()
        return false
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, window === alertPanel else { return }
        alertPanel = nil
        alertBindings = nil
        alertRow = nil
    }

    @objc private func quitApp() {
        if SentinelResidencyBuild.activationAllowed,
           sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)?.desiredLogin == true {
            let alert = OrchardPearlArt.makeAlert()
            alert.messageText = UIL("quit.confirm", "監視を停止してアプリを終了しますか")
            alert.informativeText = UIL("quit.full_consequences", "終了後と次回ログイン後も、自動監視は停止します。手動で監視再開を選ぶまで勝手に開き直しません。ログイン登録は残り、未確認変更・原文・履歴は保持します。登録解除は別の操作です。")
            alert.addButton(withTitle: UIL("quit.stop_and_quit", "監視を停止して終了"))
            alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
            alert.buttons[0].keyEquivalent = ""
            alert.buttons[1].keyEquivalent = "\r"
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            guard residencyCommand("quit") != nil else {
                showResult(UIM("quit.save_failed", "終了の選択を保存できません。自動復旧を抑止できないため終了しません。"))
                return
            }
        }
        NSApp.terminate(nil)
    }

    @objc private func openStatusMenu() {
        DispatchQueue.main.async { [weak self] in
            self?.item?.button?.performClick(nil)
        }
    }

    @objc private func reviewFirstPending() {
        withNoticeInteraction {
            refresh(forceNoticeRead: true)
            openPendingList()
        }
    }

    @objc private func primaryMonitorAction() {
        guard !targetSwitchInFlight, let snapshot = presentationSnapshot else { return }
        switch snapshot.action {
        case .chooseFolder: registerProject()
        case .stop: stopMonitor()
        case .start: startMonitor()
        case .reviewRegistration:
            guard let reason = snapshot.reason else { return }
            let alert = orchardRegistrationIssueAlert(reason, language: UILanguagePreference.shared.language)
            if alert.runModal() == .alertSecondButtonReturn { reloadRegistration() }
        case .reviewOtherRegistration: reviewOtherRegistration()
        case .checkMonitor: refresh()
        }
    }

    private func reloadRegistration() {
        applyRegistration(registrationContinuity("resolve", path: options.registrationPath,
            ownedPID: ownedWatcher?.isRunning == true ? ownedWatcher?.processIdentifier : nil))
        refresh()
    }

    private func reviewOtherRegistration() {
        guard let choice = registrationIntake, choice.status == "CHOICE" else { return }
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIL("registration.adopt_question", "見つかった登録を引き継ぎますか")
        alert.informativeText = UIL("registration.adopt_prefix", "公開版とは別の保存先です。\nプロジェクト: ") + safeLabel(choice.root) +
            UIL("registration.adopt_detail", "\n未確認変更: {p0}件。元の保存先を参照し、承認・移動・削除は行いません。監視は手動開始です。", ["p0": UIValue(choice.pendingCount)])
        alert.addButton(withTitle: UIL("registration.adopt_confirm", "確認して引き継ぐ")); alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
        alert.buttons[0].keyEquivalent = ""; alert.buttons[1].keyEquivalent = "\r"
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        applyRegistration(registrationContinuity("adopt-preview", path: options.registrationPath, expected: choice.token))
        refresh()
    }

    private func applyRegistration(_ result: RegistrationIntake) {
        registrationIntake = result
        if result.status == "READY" {
            selectedRoot = result.root; selectedStateDir = result.stateDir; registrationError = nil
            setActionMessage(result.presentationNotice)
        } else if result.status == "UNREGISTERED" {
            selectedRoot = ""; selectedStateDir = ""; registrationError = nil
            setActionMessage(.verbatim(""))
        } else {
            registrationError = "[登録確認] " + result.message
            setActionMessage(.verbatim(""))
        }
    }

    private func checkRegistrationForAction(waitForReviewLock: Bool = false) -> RegistrationIntake {
        let result = registrationContinuity("check", path: options.registrationPath, root: selectedRoot,
            stateDir: selectedStateDir, ownedPID: ownedWatcher?.isRunning == true ? ownedWatcher?.processIdentifier : nil,
            waitForReviewLock: waitForReviewLock)
        if result.status != "READY", !(waitForReviewLock && result.uiReasonCode == "STATE_BUSY") {
            applyRegistration(result)
            refresh()
        }
        return result
    }

    private func registrationReadyForAction() -> Bool {
        checkRegistrationForAction().status == "READY"
    }

    private func registerProject() {
        guard registrationIntake?.status == "UNREGISTERED", selectedRoot.isEmpty else { return }
        chooseMonitoredFolder { [weak self] root in
            guard let root else { return }
            DispatchQueue.main.async { self?.presentRegistration(for: root) }
        }
    }

    private func chooseMonitoredFolder(replacing: Bool = false, completion: @escaping (String?) -> Void) {
        let picker = NSOpenPanel()
        OrchardPearlArt.applyAppearance(to: picker)
        picker.message = replacing
            ? UIL("registration.switch.pick", "新しい監視先のフォルダを選択してください")
            : UIL("registration.pick", "監視するプロジェクトを明示的に選択してください")
        picker.canChooseDirectories = true
        picker.canChooseFiles = false
        picker.allowsMultipleSelection = false
        picker.begin { result in
            completion(result == .OK ? picker.url.map { canonicalPath($0.path) } : nil)
        }
    }

    @objc private func changeMonitoredFolder() {
        guard !targetSwitchInFlight, displayedState.permitsReview,
              let previous = registrationIntake, previous.status == "READY",
              previous.root == selectedRoot, previous.stateDir == selectedStateDir else { return }
        targetSwitchInFlight = true
        alertPanel?.close()
        renderMonitorPresentation()
        chooseMonitoredFolder(replacing: true) { [weak self] root in
            guard let self else { return }
            Task { @MainActor in
                defer { self.targetSwitchInFlight = false; self.refresh() }
                guard let root else { return }
                guard root != previous.root else {
                    self.showResult(UIM("registration.switch.same", "現在と同じフォルダです。別のフォルダを選択してください。"))
                    return
                }
                guard await self.prepareMonitorTargetSwitch(from: previous) else { return }
                self.presentRegistration(for: root, replacing: previous)
            }
        }
    }

    private func prepareMonitorTargetSwitch(from previous: RegistrationIntake) async -> Bool {
        refresh()
        let stopFailure = UIM("registration.switch.stop_failed", "監視の正常終了を確認できません。監視先の登録は変更していません。")
        if displayedState.isRunning {
            guard let watcher = ownedWatcher, watcher.isRunning,
                  monitorResponse?["pid"] as? Int == Int(watcher.processIdentifier),
                  let token = monitorResponse?["run_token"] as? String else {
                showResult(stopFailure)
                return false
            }
            let alert = OrchardPearlArt.makeAlert()
            alert.messageText = UIL("registration.switch.stop_question", "現在の監視を停止して監視先を変更しますか")
            alert.informativeText = UIL("registration.switch.stop_explain", "監視を正常に停止した後、新しいフォルダの指示ファイルを表示します。前の監視記録は保持します。この後に登録を取りやめた場合も、監視の再開には操作が必要です。")
            alert.addButton(withTitle: UIL("registration.switch.stop_confirm", "監視を停止して続ける"))
            alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
            alert.buttons[0].keyEquivalent = ""
            alert.buttons[1].keyEquivalent = "\r"
            guard alert.runModal() == .alertFirstButtonReturn else { return false }
            recoverySuppressed = true
            let stopRequestDeadline = ProcessInfo.processInfo.systemUptime + 2
            var outcome: RegistrationIntake
            repeat {
                outcome = registrationContinuity("switch-stop", path: options.registrationPath,
                    expected: previous.token, root: previous.root, stateDir: previous.stateDir,
                    ownedPID: watcher.processIdentifier, runToken: token)
                guard outcome.uiReasonCode == "STATE_BUSY", watcher.isRunning,
                      ProcessInfo.processInfo.systemUptime < stopRequestDeadline else { break }
                try? await Task.sleep(for: .milliseconds(100))
            } while watcher.isRunning && ProcessInfo.processInfo.systemUptime < stopRequestDeadline
            guard outcome.status == "READY", outcome.monitor == "STOP_REQUESTED" else {
                if outcome.status == "HOLD" { applyRegistration(outcome) }
                showResult(outcome.status == "HOLD" ? outcome.presentationMessage : stopFailure)
                return false
            }
            setActionMessage(UIM("registration.switch.stopping", "現在の監視が正常に終了するのを待っています。"))
            let deadline = ProcessInfo.processInfo.systemUptime + 8
            while watcher.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
                try? await Task.sleep(for: .milliseconds(50))
            }
            guard !watcher.isRunning, watcher.terminationReason == .exit, watcher.terminationStatus == 0 else {
                showResult(stopFailure)
                return false
            }
        }
        guard ownedWatcher?.isRunning != true else {
            showResult(stopFailure)
            return false
        }
        let result = checkStoppedRegistration(previous)
        guard result.status == "READY", result.monitor == "STOPPED" else {
            if result.status == "HOLD" { applyRegistration(result) }
            showResult(result.presentationMessage)
            return false
        }
        refresh()
        guard case .stopped = displayedState else {
            showResult(stopFailure)
            return false
        }
        setActionMessage(UIM("registration.switch.review", "現在の監視は停止中です。新しい監視先の指示ファイルを確認してください。"))
        return true
    }

    private func checkStoppedRegistration(_ previous: RegistrationIntake) -> RegistrationIntake {
        registrationContinuity("switch-check", path: options.registrationPath, expected: previous.token,
                               root: previous.root, stateDir: previous.stateDir)
    }

    private func presentRegistration(for root: String, replacing previous: RegistrationIntake? = nil) {
        let stateDir = URL(fileURLWithPath: options.registrationPath).deletingLastPathComponent()
            .appendingPathComponent("state-" + UUID().uuidString).path
        guard stateDir != root, !stateDir.hasPrefix(root == "/" ? "/" : root + "/") else {
            showResult(UIM("registration.folder_contains_state", "登録の保存先を含まない監視フォルダを選択してください。"))
            return
        }
        let (previewCode, preview, _) = callDetector("registration-preview",
                                                     root: root, stateDir: stateDir)
        guard previewCode == 0, let preview,
              let token = preview["snapshot_token"] as? String, token.count == 64,
              let entries = preview["files"] as? [[String: Any]],
              let previewRoot = preview["root"] as? String,
              canonicalPath(previewRoot) == root else {
            showResult(UIM("registration.preview_unavailable", "現在の指示ファイルを安全に一覧表示できません。登録しません。"))
            return
        }
        var details = [UIL("registration.project", "プロジェクト: {p0}", ["p0": UIValue(root)]), UIL("registration.files", "監視対象: {p0}件", ["p0": UIValue(entries.count)])]
        for entry in entries {
            guard let path = entry["path"] as? String,
                  let digest = entry["sha256"] as? String,
                  let content = entry["content"] as? String else {
                showResult(UIM("registration.preview_incomplete", "登録プレビューの内容が不完全です。登録しません。"))
                return
            }
            details.append(UIL("registration.content", "\nファイル: {p0}\nSHA-256: {p1}\n--- 原文 ---\n{p2}\n--- ここまで ---", ["p0": UIValue(path), "p1": UIValue(digest), "p2": UIValue(content)]))
        }
        if entries.isEmpty { details.append(UIL("registration.no_files", "監視対象の指示ファイルは現在ありません。今後の追加を監視します。")) }
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = previous == nil
            ? UIL("registration.ask", "このプロジェクトを登録しますか")
            : UIL("registration.switch.ask", "このフォルダを新しい監視先に登録しますか")
        alert.informativeText = UIL("registration.explain", "表示された現在の内容を確認してから登録してください。登録時の内容を信頼基準にします。監視は登録後も停止中です。")
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 700, height: 350))
        text.isEditable = false
        text.isSelectable = true
        text.isAutomaticLinkDetectionEnabled = false
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        text.string = details.joined(separator: "\n")
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 720, height: 350))
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.documentView = text
        alert.accessoryView = scroll
        alert.addButton(withTitle: UIL("registration.confirm", "この内容を確認して登録"))
        alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        finishRegistration(root: root, stateDir: stateDir, token: token, replacing: previous)
    }

    private func finishRegistration(root: String, stateDir: String, token: String, replacing previous: RegistrationIntake?) {
        if let previous {
            let stopped = checkStoppedRegistration(previous)
            guard stopped.status == "READY", stopped.monitor == "STOPPED" else {
                if stopped.status == "HOLD" { applyRegistration(stopped) }
                showResult(stopped.presentationMessage)
                return
            }
        } else {
            let intake = registrationContinuity("resolve", path: options.registrationPath)
            guard intake.status == "UNREGISTERED" else {
                applyRegistration(intake)
                refresh()
                return
            }
        }
        var initArguments = ["--confirm", "--expected-snapshot", token]
        if previous != nil { initArguments.append("--fresh-state") }
        let (initCode, _, _) = callDetector("init", arguments: initArguments, root: root, stateDir: stateDir)
        guard initCode == 0 else {
            showResult(UIM("registration.changed", "登録前の内容が変わったか、信頼基準を作れませんでした。再度内容を確認してください。"))
            return
        }
        if let previous {
            finishMonitorTargetSwitch(from: previous, root: root, stateDir: stateDir, reviewedSnapshot: token)
            return
        }
        let result = registrationContinuity("save", path: options.registrationPath, root: root, stateDir: stateDir)
        if result.status == "READY", result.root == root, result.stateDir == stateDir {
            applyRegistration(result)
            setActionMessage(UIM("monitor.stopped_after", "登録しました。監視は停止中です。"))
        } else {
            let notice = UIM("registration.pointer_failed", "作成した信頼基準は保持しています。登録情報の保存を確認できませんでした。")
            applyRegistration(result.status == "HOLD" ? result : .hold(notice))
            setActionMessage(notice)
        }
        refresh()
    }

    private func finishMonitorTargetSwitch(from previous: RegistrationIntake, root: String,
                                           stateDir: String, reviewedSnapshot: String) {
        let stored = registrationContinuity("switch", path: options.registrationPath, expected: previous.token,
            root: previous.root, stateDir: previous.stateDir, newRoot: root, newStateDir: stateDir,
            reviewedSnapshot: reviewedSnapshot)
        let readback = registrationContinuity("current", path: options.registrationPath)
        if stored.status == "READY", stored.monitor == "STOPPED", readback.status == "READY", readback.monitor == "STOPPED",
           stored.root == root, stored.stateDir == stateDir, readback.root == root, readback.stateDir == stateDir,
           !stored.token.isEmpty, readback.token == stored.token {
            ownedWatcher = nil
            startingWatcher = false
            automaticWatcher = false
            automaticStopRequested = false
            recoverySuppressed = true
            completedAlertClaims.removeAll()
            lastAlertClaimAttempt.removeAll()
            applyRegistration(stored)
        } else if stored.status == "HOLD", stored.helperExitVerified,
                  readback.status == "READY", readback.monitor == "STOPPED",
                  readback.root == previous.root, readback.stateDir == previous.stateDir, readback.token == previous.token {
            applyRegistration(readback)
            showResult(stored.presentationMessage)
        } else {
            let notice = UIM("registration.switch.unverified", "切替結果を確認できません。監視を開始せず、保存済みの登録を再確認してください。")
            applyRegistration(.hold(notice))
            showResult(notice)
        }
    }

    @objc private func startMonitor() {
        guard !targetSwitchInFlight, registrationReadyForAction() else { return }
        if SentinelResidencyBuild.activationAllowed,
           sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)?.desiredLogin == true {
            guard residencyCommand("resume", arguments: ["--human-confirmed"]) != nil else {
                showResult(UIM("monitor.start_save_failed", "監視再開の明示選択を保存できません。監視は開始しません。"))
                return
            }
            launchHelperForExplicitChoice()
        }
        recoverySuppressed = false
        launchWatcher(automatic: false)
    }

    private func launchWatcher(automatic: Bool) {
        guard !targetSwitchInFlight, case .stopped = displayedState, ownedWatcher?.isRunning != true,
              options.runtimeError == nil, let python = options.pythonPath, let detector = options.detectorPath,
              Bundle.main.bundleURL.pathExtension != "app" || SentinelRuntime.validates(python: python, script: detector) else { return }
        let process = Process()
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-I", "-S", "-B", detector, "watch", "--root", selectedRoot,
                             "--state-dir", selectedStateDir, "--quiet",
                             "--registration-file", options.registrationPath,
                             "--owner-pid", String(ProcessInfo.processInfo.processIdentifier),
                             "--run-token", token]
        process.environment = SentinelRuntime.environment
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.refresh() }
        }
        do {
            try process.run()
            ownedWatcher = process
            automaticWatcher = automatic
            automaticStopRequested = false
            startingWatcher = true
            setActionMessage(UIM("monitor.starting", "監視プロセスの起動を確認中"))
            if !automatic { refresh() }
        } catch {
            if automatic {
                setActionMessage(UIM("monitor.recovery_failed", "自動復旧を試せませんでした。有限回数で打ち切ります。未確認証拠は保持しています。"))
            } else {
                showResult(UIM("monitor.start_failed", "監視プロセスを起動できませんでした。未確認証拠は保持しています。"))
            }
        }
    }

    @objc private func stopMonitor() {
        recoverySuppressed = true
        if SentinelResidencyBuild.activationAllowed,
           sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)?.desiredLogin == true {
            guard residencyCommand("pause") != nil else {
                showResult(UIM("monitor.stop_save_failed", "停止の選択を保存できません。実際の停止状態を確認してください。"))
                if let ownedWatcher, ownedWatcher.isRunning { ownedWatcher.interrupt() }
                else if let token = monitorResponse?["run_token"] as? String {
                    _ = callDetector("monitor-stop", arguments: ["--run-token", token])
                }
                return
            }
        }
        guard case .running = displayedState,
              let token = monitorResponse?["run_token"] as? String else { return }
        let (status, outcome, _) = callDetector("monitor-stop", arguments: ["--run-token", token])
        if status == 0 && outcome?["result"] as? String == "STOP_REQUESTED" {
            setActionMessage(UIM("monitor.stop_requested", "監視停止を要求しました。未確認証拠は保持します。"))
            refresh()
        } else {
            showResult(UIM("monitor.stop_unverified", "監視停止を確認できませんでした。状態を再確認してください。"))
        }
    }

    private func residencyCommand(_ action: String, arguments: [String] = []) -> [String: Any]? {
        guard let python = options.pythonPath,
              let script = Bundle.main.resourceURL?.appendingPathComponent("residency.py").path else { return nil }
        return sentinelResidencyCommand(python: python, script: script, root: selectedRoot,
                                         stateDir: selectedStateDir, action: action, arguments: arguments)
    }

    private func reconcileResidency(state: DisplayState, registration: SentinelRegistration,
                                    policy: SentinelPolicyView?) {
        guard SentinelResidencyBuild.activationAllowed, !residencyMutationInFlight, !targetSwitchInFlight else { return }
        guard let policy, !recoverySuppressed else {
            if automaticWatcher, let ownedWatcher, ownedWatcher.isRunning, !automaticStopRequested {
                ownedWatcher.interrupt()
                automaticStopRequested = true
            }
            return
        }
        if !policy.desiredMonitor || registration != .enabled {
            if automaticWatcher, let ownedWatcher, ownedWatcher.isRunning, !automaticStopRequested {
                if policy.desiredMonitor { _ = residencyCommand("os-disabled") }
                ownedWatcher.interrupt()  // only this app's own direct child
                automaticStopRequested = true
            }
            return
        }
        guard policy.desiredLogin, case .stopped = state,
              ownedWatcher?.isRunning != true, Date() >= nextRecoveryProbe else { return }
        nextRecoveryProbe = Date().addingTimeInterval(2)
        guard let outcome = residencyCommand("admit", arguments: ["--kind", "watcher"]) else {
            recoverySuppressed = true
            setActionMessage(UIM("monitor.recovery_unknown", "復旧判断を確認できません。自動復旧を止め、未確認変更を保持しています。"))
            return
        }
        if outcome["action"] as? String == "START" {
            launchWatcher(automatic: true)
        } else if outcome["action"] as? String == "WAIT",
                  let due = outcome["retry_at_epoch"] as? Double {
            nextRecoveryProbe = Date(timeIntervalSince1970: due)
        } else if outcome["action"] as? String == "PAUSED" {
            setActionMessage(UIM("monitor.recovery_stopped", "自動復旧を停止しました。手動で監視再開を選んでください。未確認変更は保持しています。"))
        }
    }

    @objc private func enableResidency() {
        guard SentinelResidencyBuild.activationAllowed else {
            showResult(UIM("residency.disabled_candidate", "常駐の実装候補です。実機登録は別Gateのため無効です。ログイン項目や監視希望は変更していません。"))
            return
        }
        guard !residencyMutationInFlight,
              options.runtimeError == nil, let runtime = try? SentinelRuntime.load(),
              options.pythonPath == runtime.python, options.detectorPath == runtime.detector,
              options.registrationPath == SentinelResidencyBuild.registrationPath,
              Bundle.main.bundleIdentifier == SentinelResidencyBuild.mainID,
              let saved = sentinelPrivateObject(options.registrationPath),
              saved["root"] as? String == selectedRoot,
              saved["state_dir"] as? String == selectedStateDir else {
            showResult(UIM("residency.identity_invalid", "常駐用の登録情報とアプリidentityを確認できません。登録しません。"))
            return
        }
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIL("residency.enable_question", "ログイン時の監視を有効にしますか")
        alert.informativeText = UIL("residency.enable_consequences", "選択済みプロジェクトを次回ログイン時にも監視します。クラッシュ時は有限回数で復旧します。変更の承認・ファイル実行・外部送信は行いません。監視停止や終了後も未確認変更は保持し、ログイン登録の解除は別に表示します。macOSの承認が必要な場合があります。")
        alert.addButton(withTitle: UIL("residency.enable_confirm", "この説明を確認して有効にする"))
        alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard residencyCommand("enable", arguments: ["--human-confirmed"]) != nil else {
            showResult(UIM("residency.precheck_failed", "明示選択か信頼基準を確認できません。登録しません。"))
            return
        }
        recoverySuppressed = false
        do {
            try loginService.register()
            launchHelperForExplicitChoice()
            showResult(UIM("residency.os_status", "macOSのログイン項目: {p0}。登録状態だけで監視中とは判断しません。", ["p0": UIValue(loginService.status.japanese)]))
        } catch {
            showResult(UIM("residency.register_failed", "ログイン登録を完了できません。macOSの状態: {p0}。保存希望と登録状態は別です。", ["p0": UIValue(loginService.status.japanese)]))
        }
        refresh()
    }

    private func launchHelperForExplicitChoice() {
        guard SentinelResidencyBuild.activationAllowed, loginService.status == .enabled,
              Bundle.main.bundleIdentifier == SentinelResidencyBuild.mainID else { return }
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LoginItems/OrchardSentinelLogin.app")
        guard Bundle(url: helper)?.bundleIdentifier == SentinelResidencyBuild.helperID else { return }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = false
        configuration.createsNewApplicationInstance = false
        // Explicit enable/resume can recover a helper that exited cleanly on HOLD.
        // Timer refresh never launches a helper or changes login registration.
        NSWorkspace.shared.openApplication(at: helper, configuration: configuration) { _, _ in }
    }

    @objc private func disableResidency() {
        guard SentinelResidencyBuild.activationAllowed else {
            showResult(UIM("residency.change_disabled", "候補buildではOS登録の変更は無効です。現在の監視停止は「監視を停止」から選べます。"))
            return
        }
        guard !residencyMutationInFlight else { return }
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIL("residency.disable_question", "ログイン登録を解除し、監視を停止しますか")
        alert.informativeText = UIL("residency.disable_consequences", "次回ログインの自動監視と自動復旧を止めます。未確認変更・原文・承認履歴は削除しません。解除に失敗した場合はmacOSの実際の登録状態を表示します。")
        alert.addButton(withTitle: UIL("residency.disable_confirm", "登録を解除して監視を停止"))
        alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        recoverySuppressed = true
        residencyMutationInFlight = true
        let saved = residencyCommand("disable") != nil
        if let ownedWatcher, ownedWatcher.isRunning { ownedWatcher.interrupt() }
        else if let token = monitorResponse?["run_token"] as? String {
            _ = callDetector("monitor-stop", arguments: ["--run-token", token])
        }
        loginService.unregister { [weak self] succeeded in
            guard let self else { return }
            self.residencyMutationInFlight = false
            self.showResult(UIM("residency.disable_status", "macOSのログイン項目: {p0}。{p1}監視の停止完了はleaseとscanで別に確認します。未確認変更は保持しています。", ["p0": UIValue(self.loginService.status.japanese), "p1": UIValue(succeeded && saved ? UIM("residency.disable_saved", "解除の応答と停止希望の保存を確認しました。") : UIM("residency.disable_incomplete", "解除または保存を完了できていません。"))]))
            self.refresh()
        }
    }

    private func callDetector(_ command: String, arguments: [String] = [],
                              root: String? = nil, stateDir: String? = nil) -> (Int32, [String: Any]?, String) {
        if ["review", "accept", "dismiss-notice", "claim-alert", "md-history", "md-history-event"].contains(command) {
            let requestedRoot = root ?? selectedRoot
            let requestedState = stateDir ?? selectedStateDir
            let checked = checkRegistrationForAction(waitForReviewLock: true)
            guard checked.status == "READY" else {
                let message = checked.uiReasonCode == "STATE_BUSY"
                    ? UIL("review.registration_busy", "監視が保存状態を更新中です。少し待ってから、未確認の変更をもう一度開いてください。")
                    : checked.presentationMessage.text
                return (78, ["result": "REFUSED_REGISTRATION"], message)
            }
            guard !targetSwitchInFlight, checked.root == requestedRoot, checked.stateDir == requestedState,
                  requestedRoot == selectedRoot, requestedState == selectedStateDir else {
                return (78, ["result": "REFUSED_REGISTRATION"],
                    UIL("registration.reason.changed", "確認中に監視先が変わりました。現在の登録と変更を再確認してください。"))
            }
        } else if !["registration-preview", "init"].contains(command), !registrationReadyForAction() {
            return (78, nil, UIL("registration.state_unverified", "登録・保存状態を確認できません。記録は保持しています。"))
        }
        return runDetector(options: options, root: root ?? selectedRoot,
                           stateDir: stateDir ?? selectedStateDir,
                           command: command, arguments: arguments)
    }

    private func showResult(_ message: UIMessage) {
        setActionMessage(message)
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = "Orchard"
        alert.informativeText = message.text
        alert.addButton(withTitle: UIL("ui.common.close", "閉じる"))
        alert.runModal()
    }

    private func reviewReason(_ raw: String) -> UIMessage {
        switch raw {
        case "Trusted old content was not saved; a safe diff is unavailable":
            return UIM("review.diff_old_missing", "信頼済みの旧内容が保存されていないため、差分を作れません。")
        case "Saved old content disagrees with the trusted hash":
            return UIM("review.diff_hash_mismatch", "保存された旧内容と信頼基準のハッシュが一致しません。")
        case "Saved baseline cannot establish absence before addition":
            return UIM("review.diff_absence", "追加前に対象がなかったことを保存済みの基準から確認できません。既存の記録を残し、監視登録と基準を再確認してください。")
        case "Baseline and pending state disagree", "Saved review state cannot be verified":
            return UIM("review.diff_state", "保存済みの基準と検出記録の整合を確認できません。既存の記録を残し、監視登録を再確認してください。")
        case "Current instruction scan is incomplete":
            return UIM("review.diff_incomplete", "指示ファイルの読み取りが今回の走査で完了しませんでした。対象フォルダの読み取り権限と検査範囲を確認し、再検出後に開いてください。")
        case "Deleted target has no current text for approval":
            return UIM("review.diff_deleted", "削除されたため承認に使える現在の原文がありません。削除記録は未確認のまま保持します。")
        case "Target exceeds the 64 KiB comparison cap":
            return UIM("review.diff_size", "対象が比較上限の64 KiBを超えています。")
        case "Target is not valid UTF-8":
            return UIM("review.diff_utf8", "対象をUTF-8のテキストとして安全に表示できません。")
        case "Target is not a regular file", "Target is unreadable or unsafe", "Pending evidence has no readable target":
            return UIM("review.diff_unsafe", "対象が通常ファイルではないか、安全に読み取れません。ファイルの種類と読み取り権限を確認し、再検出後に開いてください。")
        case "Current target no longer matches pending evidence", "Current content changed during review",
             "Addition no longer matches the last observation", "Target changed while opening", "Target changed while reading":
            return UIM("review.diff_changed", "対象が検知時から変わりました。再検出後に確認してください。")
        case "Diff cannot be compared safely within the PoC limit":
            return UIM("review.diff_limit", "差分が表示上限を超えています。")
        default:
            return UIM("review.diff_unknown", "保存状態または対象を安全に比較できません。再検出後に確認してください。")
        }
    }

    private func acceptReason(_ raw: String) -> UIMessage {
        switch raw {
        case "REFUSED_CHANGED_AFTER_REVIEW":
            return UIM("review.review_changed", "確認後に内容または検出状態が変わりました。改めて確認してください。")
        case "REFUSED_CHANGED_DURING_ACCEPT":
            return UIM("review.accept_changed", "承認処理中に内容が変わりました。未確認状態は保持しています。")
        case "REFUSED_CHANGED_OR_UNSAFE":
            return UIM("review.accept_precheck_failed", "承認直前に対象を安全に再検査できませんでした。未確認状態は保持しています。")
        default:
            return UIM("review.accept_failed", "承認できませんでした。未確認状態と履歴を確認してください。")
        }
    }

    private func evidenceText(_ raw: String) -> String {
        var value = "\""
        for scalar in raw.unicodeScalars {
            switch scalar.value {
            case 0x22: value += "\\\""
            case 0x5c: value += "\\\\"
            case 0x09: value += "\\t"
            case 0x0A: value += "\\n"
            case 0x0D: value += "\\r"
            case 0x00...0x1F, 0x7F...0x9F, 0x202A...0x202E, 0x2066...0x2069:
                value += "\\u{\(String(scalar.value, radix: 16))}"
            default: value += String(scalar)
            }
        }
        return value + "\""
    }

    private func impactText(_ ja: String, _ en: String) -> String {
        UILanguagePreference.shared.language == .ja ? ja : en
    }

    private func impactRule(_ rule: MonitorImpactReview.Rule) -> String {
        switch rule {
        case .quoted: return impactText("引用・例として記載", "appears in a quotation or example")
        case .text: return impactText("表記・説明の変更", "changes wording or formatting")
        case .procedure: return impactText("作業手順を指定", "specifies a work procedure")
        case .restriction: return impactText("行動に制限を指定", "states a restriction")
        case .expansion: return impactText("行動範囲や既存制約の変更を要求", "requests a broader scope or a change to existing constraints")
        case .transfer: return impactText("外部送信を要求", "requests an external transfer")
        case .sensitive: return impactText("機密情報の取り扱いを要求", "requests handling of sensitive data")
        case .destructive: return impactText("削除・消去を要求", "requests deletion or erasure")
        case .approvalBypass: return impactText("承認を省くよう要求", "requests bypassing approval")
        case .falseApproval: return impactText("変更を承認済みとして扱うよう要求", "requests treating changes as already approved")
        case .falseReviewCompletion: return impactText("レビューを完了扱いにするよう要求", "requests treating the review as complete")
        case .unknown: return impactText("この行の行動は不明", "action on this line is unclear")
        }
    }

    private func impactDestination(_ value: MonitorImpactReview.Destination) -> String {
        let relation: String
        switch value.relation {
        case .added: relation = impactText("送信先を新規追加", "New transfer destination")
        case .changed: relation = impactText("送信先を変更", "Changed transfer destination")
        case .unchanged: relation = impactText("同じ送信先を参照", "References an existing transfer destination")
        case .unlinked: relation = impactText("送信要求との関係不明", "Relationship to a transfer request is unclear")
        case .dynamic: relation = impactText("動的指定・宛先特定不能", "Dynamic or unspecified destination")
        }
        let verdict: String
        switch value.lookup.status {
        case .match: verdict = impactText("既知悪性情報に一致", "Match to known-malicious intelligence")
        case .noMatch: verdict = impactText("既知情報に一致なし", "No match in the checked intelligence")
        case .unverified: verdict = impactText("未照合", "Unchecked")
        }
        let scopes = (value.lookup.status == .match ? value.lookup.matches : value.lookup.scopes).map {
            $0 == .url ? impactText("完全URL", "Exact URL") : impactText("完全ホスト名", "Exact host")
        }.joined(separator: ", ")
        let previous = value.previous_hosts.isEmpty ? "" : impactText("・変更前 ", " · Previous ") + value.previous_hosts.joined(separator: ", ")
        return impactText("変更後の行 ", "After line ") + String(value.line) + "  " + relation
            + (value.host.map { " · " + $0 } ?? "") + previous + "\n  " + verdict + (scopes.isEmpty ? "" : " · " + scopes)
    }

    private func impactSummary(_ row: ChangeRow, _ model: MonitorImpactReview?, _ explanation: UIMessage?) -> String {
        let unknown = impactText("不明", "Unknown")
        let level = model?.level.map(String.init) ?? unknown
        let scope: String
        switch model?.scope ?? .unknown {
        case .expanded: scope = impactText("拡大", "Expanded")
        case .same: scope = impactText("拡大なし", "No expansion found")
        case .unknown: scope = unknown
        }
        let future: String
        switch model?.future_use ?? .unknown {
        case .possible: future = impactText("対象のAIがこの指示ファイルを読めば、今後も使われる可能性があります。", "May apply in later work if the AI reads this instruction file.")
        case .none: future = impactText("比較できた変更には新しい有効な指示が見つかりません。", "The reviewed change shows no new active directive.")
        case .unknown: future = impactText("今後の適用は確認できません。", "Future applicability is unknown.")
        }
        let describedLevel = model?.coverage == .partial && model?.level != nil
            ? impactText("少なくとも ", "At least ") + level : level
        var lines = [
            impactText("変更 ", "Change ") + localizedKind(row.kind).text,
            impactText("影響レベル ", "Impact level ") + describedLevel,
            impactText("指示上の行動範囲 ", "Requested scope ") + scope,
            future,
            impactText("元の依頼は取得していません。判定は変更された指示文に基づきます。", "The original request is unavailable. The assessment uses the changed instruction text."),
            impactText("OS・API権限と実際の送信や実行は未確認です。監視にAIの実行を止める機能はありません。", "OS and API permissions, actual transfers, and execution are unverified. Monitoring does not stop AI execution.")
        ]
        if let explanation { lines.append("\n" + explanation.text) }
        if let model {
            if model.unknown_lines > 0 {
                lines.append(impactText("分類できない変更後の行 ", "Unclassified changed lines ") + String(model.unknown_lines))
            }
            for limit in model.limits {
                switch limit {
                case .analysis: lines.append(impactText("分析上限を超えました。原文と差分で確認してください。", "The analysis limit was exceeded. Use the original text and diff."))
                case .evidence: lines.append(impactText("根拠の抜粋を表示しています。残りは差分で確認できます。", "Only selected evidence is shown. The diff contains the remaining lines."))
                case .destinations: lines.append(impactText("送信先候補の表示上限に達しました。", "The destination display limit was reached."))
                }
            }
            if !model.evidence.isEmpty { lines.append("\n" + impactText("変更行と判定根拠", "Changed lines and evidence")) }
            for evidence in model.evidence {
                let side = evidence.side == .before ? impactText("変更前の行 ", "Before line ") : impactText("変更後の行 ", "After line ")
                let original = String(evidence.original.prefix(480))
                lines.append(side + String(evidence.line) + "  " + evidenceText(original) + (original == evidence.original ? "" : "…"))
                var reasons = evidence.actions.map(impactRule)
                if evidence.persistent { reasons.append(impactText("継続適用の明記", "explicit recurring use")) }
                if evidence.skips_approval && !evidence.actions.contains(.approvalBypass) {
                    reasons.append(impactText("承認省略の明記", "explicit approval bypass"))
                }
                if evidence.irreversible { reasons.append(impactText("復元困難な処理の明記", "explicit hard-to-reverse action")) }
                lines.append("  " + reasons.joined(separator: " · "))
            }
        }
        lines.append("\n" + impactText("送信先候補と脅威情報", "Destination candidates and threat intelligence"))
        if let model, !model.destinations.isEmpty {
            lines.append(contentsOf: model.destinations.map(impactDestination))
        } else {
            lines.append(model?.coverage == .described
                ? impactText("変更箇所に表示できる送信先候補は見つかりません。", "No destination candidate was extracted from the changes.")
                : impactText("送信先は特定できず、未照合です。", "Destinations are unresolved and unchecked."))
        }
        if let intelligence = model?.intelligence {
            let source = intelligence.source == .urlhaus ? "URLhaus" : impactText("合成テストデータ", "Synthetic test data")
            let freshness: String
            switch intelligence.state {
            case .ready: freshness = impactText("オフライン照合表を確認", "Verified offline index")
            case .missing: freshness = impactText("検証済み照合表なし・未照合", "No verified index; unchecked")
            case .stale: freshness = impactText("期限外・未照合", "Outside freshness window; unchecked")
            case .invalid: freshness = impactText("整合未確認・未照合", "Integrity unverified; unchecked")
            }
            lines.append(impactText("情報源 ", "Source ") + source + " · " + freshness)
            lines.append(impactText("取得日時 ", "Retrieved ") + (intelligence.retrieved_at_utc ?? unknown))
        }
        lines.append(impactText("一致の有無だけでは安全性や送信先の運営者・攻撃者の身元は判定できません。", "Lookup results do not establish safety or identify a destination operator or attacker."))
        return lines.joined(separator: "\n")
    }

    private func impactScroll(_ contents: String, height: CGFloat = 360) -> NSScrollView {
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 700, height: height))
        text.isEditable = false
        text.isSelectable = true
        text.isAutomaticLinkDetectionEnabled = false
        text.isAutomaticDataDetectionEnabled = false
        text.font = .systemFont(ofSize: 13)
        text.textContainer?.widthTracksTextView = true
        text.string = contents
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 720, height: height))
        scroll.hasVerticalScroller = true
        scroll.documentView = text
        return scroll
    }

    private func investigateImpactDestinations(_ model: MonitorImpactReview) {
        let hosts = Set(model.destinations.compactMap(\.host)).sorted()
        guard !hosts.isEmpty else { return }
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = impactText("送信先を外部で調べる", "Investigate a destination externally")
        alert.informativeText = impactText(
            "Orchardが開くページは https://urlhaus.abuse.ch/browse/ です。検索語は付きません。外部に共有してよいホスト名を確認し、必要なものだけ検索欄に手入力してください。",
            "Orchard opens https://urlhaus.abuse.ch/browse/ without a search term. Check which host names you can share and type only the intended term into the external search field.")
        alert.accessoryView = impactScroll(hosts.joined(separator: "\n"), height: 100)
        alert.addButton(withTitle: impactText("URLhausを開く", "Open URLhaus"))
        let cancel = alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
        alert.buttons[0].keyEquivalent = ""
        cancel.keyEquivalent = "\r"
        if alert.runModal() == .alertFirstButtonReturn, let page = URL(string: "https://urlhaus.abuse.ch/browse/") {
            NSWorkspace.shared.open(page)
        }
    }

    private func blockedReviewReason(_ explanation: UIMessage?, result: String?) -> String {
        if result == "REFUSED_REGISTRATION" {
            return impactText("監視登録を照合できません。", "The monitoring registration could not be verified.")
        }
        switch explanation?.key {
        case "review.registration_busy":
            return impactText("監視が記録を更新中です。", "Monitoring is updating the stored records.")
        case "review.diff_changed":
            return impactText("検知時と現在の原文が異なります。", "The current text differs from the detected version.")
        case "review.diff_incomplete":
            return impactText("今回の読み取りは未完了です。", "The current scan could not finish reading the files.")
        case "review.diff_deleted":
            return impactText("削除後の原文がありません。", "The deleted file has no current text.")
        case "review.diff_size", "review.diff_limit":
            return impactText("原文または差分が比較上限を超えています。", "The original or diff exceeds the comparison limit.")
        case "review.diff_unsafe", "review.diff_utf8":
            return impactText("原文を安全に読み取れません。", "The original text could not be read safely.")
        default:
            return impactText("承認に必要な原文または保存記録を照合できません。", "Text or records required for approval could not be verified.")
        }
    }

    private func confirmBaselineAcceptance(_ row: ChangeRow) -> Bool {
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = impactText("この変更を監視基準に反映", "Accept this change into the monitoring baseline")
        alert.informativeText = row.path + "\n\n" + impactText(
            "確認した内容を今後の比較基準にします。安全性は別に確認してください。",
            "The reviewed content becomes the basis for future comparisons. Assess safety separately.")
        alert.addButton(withTitle: impactText("監視基準に反映する", "Accept into baseline")).keyEquivalent = ""
        let cancel = alert.addButton(withTitle: impactText("戻る", "Go back"))
        return InstructionReviewModal.confirms(alert, cancel: cancel)
    }

    private struct MDHistoryRow: Decodable {
        let id: String
        let sequence: Int
        let kind: String
        let path: String?
        let observed_epoch: Double?
        let capture: Int?
        let approval: String
        let level: Int?
        let text_incomplete: Bool

        var valid: Bool {
            id.utf8.count == 64 && id.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil
                && sequence > 0 && (observed_epoch.map { $0.isFinite && $0 >= 0 } ?? true)
                && (level.map { (1...5).contains($0) } ?? true)
        }
    }

    private struct MDHistoryPage: Decodable {
        let root: String
        let total: Int
        let rows: [MDHistoryRow]
        let storage: String?
        let legacy: Bool
        let initialized: Bool
        let incomplete_scans: Int
        let older_before: Int?
        let is_latest_page: Bool
        let has_previous: Bool
        let previous_unverified: Bool
    }

    private enum MDHistoryChoice {
        case event(MDHistoryRow)
        case page(Int)
        case target(Int)
    }

    private func mdHistoryKind(_ value: String) -> String {
        switch value {
        case "RETURNED": return impactText("承認基準と同じ内容に戻った", "Returned to the approved baseline")
        case "LEGACY_PENDING": return impactText("旧版の保存済み未確認記録", "Pending record retained from an older version")
        case "FIRST_OBSERVED": return impactText("内容を初めて取得", "First available observation")
        case "GAP": return impactText("観測の欠落・不明", "Observation gap or uncertainty")
        case "UNVERIFIED": return impactText("履歴の一部を検証できない", "Observation record unverified")
        default: return localizedKind(value).text
        }
    }

    private func mdHistoryApproval(_ value: String) -> String? {
        switch value {
        case "APPROVED": return impactText("基準へ反映済み", "Approved into the baseline")
        case "DISMISSED": return impactText("未承認・通知終了", "Unapproved · notification dismissed")
        case "UNAPPROVED": return impactText("未承認", "Unapproved")
        case "UNVERIFIED": return impactText("承認状態は未確認", "Approval status unverified")
        default: return nil
        }
    }

    private func mdHistoryRowTitle(_ row: MDHistoryRow) -> String {
        let date = row.observed_epoch.map { Date(timeIntervalSince1970: $0) }
        var parts = ["#\(row.sequence)", localizedTimestamp(date).text, mdHistoryKind(row.kind)]
        if let path = row.path { parts.append(safeLabel(path)) }
        if let level = row.level { parts.append(impactText("保存した影響レベル ", "Recorded impact level ") + String(level)) }
        if let approval = mdHistoryApproval(row.approval) { parts.append(approval) }
        if row.text_incomplete { parts.append(impactText("原文・差分に未取得あり", "Text or diff incomplete")) }
        return parts.joined(separator: " · ")
    }

    private func mdHistoryReadFailure(_ object: [String: Any]?, _ raw: String) -> UIMessage {
        switch object?["result"] as? String {
        case "NOTICE_BUSY", "REFUSED_REGISTRATION": return noticeFailureReason(object, raw)
        default:
            return .verbatim(impactText("保存済み履歴を検証できません。未取得・破損している箇所があります。",
                                       "The saved history could not be verified. Some evidence is unavailable."))
        }
    }

    @objc private func openMDHistory() {
        withNoticeInteraction { browseMDHistory(root: selectedRoot, stateDir: selectedStateDir) }
    }

    private func browseMDHistory(root: String, stateDir: String) {
        var depth = 0, before = 0
        while true {
            let (status, object, raw) = callDetector("md-history", arguments: [
                "--history-depth", String(depth), "--history-before", String(before)
            ], root: root, stateDir: stateDir)
            guard status == 0, let object, object["result"] as? String == "HISTORY_READY",
                  let data = try? JSONSerialization.data(withJSONObject: object), data.count <= 192 * 1024,
                  let page = try? JSONDecoder().decode(MDHistoryPage.self, from: data),
                  (0...2048).contains(page.total), page.rows.count <= 24, page.rows.allSatisfy(\.valid),
                  page.older_before.map({ (2...2048).contains($0) }) ?? true else {
                showResult(mdHistoryReadFailure(object, raw))
                return
            }
            guard let choice = chooseMDHistory(page, depth: depth) else { return }
            switch choice {
            case .event(let row): showMDHistoryEvent(row, depth: depth, root: root, stateDir: stateDir)
            case .page(let sequence): before = sequence
            case .target(let value): depth = value; before = 0
            }
        }
    }

    private func chooseMDHistory(_ page: MDHistoryPage, depth: Int) -> MDHistoryChoice? {
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIL("monitor.history.open", "変更履歴") + " · " + safeLabel(page.root)
        var copy = [impactText("保存された観測記録 ", "Saved observations ") + String(page.total),
                    impactText("走査で確認できた順序です。走査の間の一時的な版や、同じ走査内での書き込み順は確認できません。",
                               "Records follow observation order. Intermediate writes between scans and write order within a scan are unknown.")]
        if page.legacy { copy.append(impactText("旧版で取得していない中間版は履歴に含まれません。", "Intermediate versions never captured by older builds are unavailable.")) }
        if !page.initialized { copy.append(impactText("監視で履歴を記録する最初の走査を待っています。", "Waiting for the first scan that can record history.")) }
        if page.incomplete_scans > 0 { copy.append(impactText("欠落・不明の記録 ", "Entries marking gaps or uncertainty ") + String(page.incomplete_scans)) }
        if page.previous_unverified { copy.append(impactText("前の監視先への参照を検証できません。", "The link to the previous monitoring target could not be verified.")) }
        if page.storage != nil {
            copy.append(page.storage == "CAPACITY"
                ? impactText("履歴の保全上限に達しました。保存済みの履歴は残り、新しい走査の証拠には未記録の範囲があります。",
                             "The retention limit was reached. Saved records remain available and newer scans may be missing from this history.")
                : impactText("履歴の保存が中断しました。新しい走査の証拠を検証できません。", "History recording was interrupted. Newer scan evidence could not be verified."))
        }
        alert.informativeText = copy.joined(separator: "\n")
        alert.addButton(withTitle: UIL("ui.common.close", "閉じる"))
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 690, height: 26), pullsDown: false)
        picker.menu?.autoenablesItems = false
        var choices: [MDHistoryChoice] = []
        func add(_ title: String, _ choice: MDHistoryChoice) {
            let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            item.tag = choices.count
            picker.menu?.addItem(item)
            choices.append(choice)
        }
        for row in page.rows { add(mdHistoryRowTitle(row), .event(row)) }
        if let sequence = page.older_before { add(impactText("さらに古い記録", "Older records"), .page(sequence)) }
        if !page.is_latest_page { add(impactText("最新の記録", "Newest records"), .page(0)) }
        if page.has_previous { add(impactText("前の監視先の履歴", "History of the previous target"), .target(depth + 1)) }
        if depth > 0 { add(impactText("次の監視先の履歴", "History of the newer target"), .target(depth - 1)) }
        if !choices.isEmpty {
            picker.selectItem(at: max(0, page.rows.count - 1))
            picker.setAccessibilityLabel(UIL("monitor.history.open", "変更履歴"))
            alert.accessoryView = picker
            alert.addButton(withTitle: impactText("選択した項目を開く", "Open selected item"))
        }
        guard alert.runModal() == .alertSecondButtonReturn,
              let selected = picker.selectedItem?.tag, choices.indices.contains(selected) else { return nil }
        return choices[selected]
    }

    private func mdGapDescription(_ reason: String) -> String {
        switch reason {
        case "SCAN_INCOMPLETE": return impactText("走査中に内容を読み取れない対象、上限またはパスの曖昧さがありました。", "A read error, scope limit, or ambiguous path affected this scan.")
        case "SAME_CONTENT_WRITE_UNCERTAIN": return impactText("内容のハッシュは同じですが、ファイル情報が変わりました。取得できなかった中間版の有無は不明です。", "File metadata changed while the content hash stayed the same. Intermediate writes are unknown.")
        case "MONITORING_RESUMED": return impactText("監視を再開しました。停止中は観測していません。", "Monitoring resumed. Changes while monitoring was stopped were unobserved.")
        case "RECORDING_INTERRUPTED": return impactText("前回の保存中断後に記録を再開しました。中断中の証拠は不完全です。", "Recording resumed after an interruption. Evidence from the interruption is incomplete.")
        default: return impactText("欠落の理由を検証できません。", "The reason for the gap could not be verified.")
        }
    }

    private func mdCapturedText(_ raw: Any?) -> String {
        guard let saved = raw as? [String: Any], (saved["known"] as? Bool) == true else {
            return impactText("未確認", "Unverified")
        }
        guard let hash = saved["sha256"] as? String else { return impactText("対象ファイルなし", "File absent") }
        guard let text = saved["text"] as? String else { return "SHA-256 " + hash + "\n" + impactText("原文は取得できませんでした。", "Original text is unavailable.") }
        let escaped = text.split(separator: "\n", omittingEmptySubsequences: false).map { evidenceText(String($0)) }
        return "SHA-256 " + hash + "\n" + escaped.joined(separator: "\n")
    }

    private func mdSavedComparison(_ raw: Any?, row: MDHistoryRow) -> String {
        guard let value = raw as? [String: Any] else { return impactText("差分は未確認です。", "The diff is unverified.") }
        if value["status"] as? String == "EQUAL" { return impactText("差分なし。取得した内容は比較元と一致。", "No diff. The observed content matches this comparison point.") }
        guard let diff = value["diff"] as? String else { return impactText("原文を取得できず、差分と影響は不明です。", "The original was unavailable. The diff and impact are unknown.") }
        let visible = diff.split(separator: "\n", omittingEmptySubsequences: false).map { evidenceText(String($0)) }.joined(separator: "\n")
        guard let impact = value["impact"] as? [String: Any], let kind = impact["kind"] as? String,
              let model = MonitorImpactReview.decode(impact, kind: kind) else {
            return visible + "\n\n" + impactText("保存済みの影響判定を確認できません。", "The saved impact assessment could not be verified.")
        }
        let path = row.path ?? ""
        let change = ChangeRow(id: row.id, path: safeLabel(path), filename: safeLabel((path as NSString).lastPathComponent),
                               kind: kind, detectedAt: nil,
                               lastActivityEpoch: 0, dismissed: row.approval == "DISMISSED")
        return impactSummary(change, model, nil) + "\n\n" + visible
    }

    private func showMDHistoryEvent(_ row: MDHistoryRow, depth: Int, root: String, stateDir: String) {
        let (status, object, raw) = callDetector("md-history-event", arguments: [
            "--history-depth", String(depth), "--history-record", row.id
        ], root: root, stateDir: stateDir)
        guard status == 0, object?["result"] as? String == "HISTORY_EVENT",
              let entry = object?["entry"] as? [String: Any], entry["id"] as? String == row.id,
              let data = try? JSONSerialization.data(withJSONObject: entry),
              let latest = try? JSONDecoder().decode(MDHistoryRow.self, from: data), latest.valid,
              let event = object?["event"] as? [String: Any], event["sequence"] as? Int == row.sequence else {
            showResult(mdHistoryReadFailure(object, raw))
            return
        }
        var contents = [mdHistoryRowTitle(latest)]
        if let group = latest.capture { contents.append(impactText("走査グループ ", "Scan group ") + String(group)) }
        if latest.kind == "GAP" {
            contents += (event["reasons"] as? [String] ?? []).map(mdGapDescription)
        } else {
            switch event["anchor"] as? String {
            case "BASELINE": contents.append(impactText("初回比較の起点は保存済み承認基準です。", "The saved approved baseline is the first comparison point."))
            case "LEGACY": contents.append(impactText("旧台帳の証拠を引き継ぎました。直前の版は未取得の場合があります。", "Evidence was retained from the previous ledger. The preceding version may be missing."))
            default: break
            }
            contents.append("\n" + impactText("前回観測との差分", "Diff from the previous observation") + "\n" + mdSavedComparison(event["step"], row: latest))
            contents.append("\n" + impactText("当時の承認基準からの累積差分", "Cumulative diff from the approved baseline at capture")
                            + "\n" + mdSavedComparison(event["cumulative"], row: latest))
            for (key, title) in [("previous", impactText("比較元の原文", "Previous comparison text")),
                                 ("current", impactText("今回観測の原文", "Observed original text")),
                                 ("baseline", impactText("当時の承認基準の原文", "Original approved baseline at capture"))] {
                contents.append("\n" + title + "\n" + mdCapturedText(event[key]))
            }
        }
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIL("monitor.history.open", "変更履歴") + " #\(latest.sequence)"
        alert.accessoryView = impactScroll(contents.joined(separator: "\n"), height: 440)
        alert.addButton(withTitle: UIL("ui.common.close", "閉じる"))
        alert.runModal()
    }

    private func withNoticeInteraction(_ action: () -> Void) {
        guard !noticeInteractionInFlight, !targetSwitchInFlight else { return }
        noticeInteractionInFlight = true
        defer {
            noticeInteractionInFlight = false
            refresh()
        }
        action()
    }

    private func openPendingList() {
        let rows = displayedState.rows
        guard let first = rows.first else {
            setActionMessage(presentationSnapshot?.reason ?? UIM("monitor.pending.none", "未確認の変更はありません"))
            return
        }
        if rows.count == 1 {
            reviewNotice(first)
            return
        }
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIL("monitor.review_pending", "未確認の変更を確認")
        let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 480, height: 26), pullsDown: false)
        picker.menu?.autoenablesItems = false
        for (index, row) in rows.enumerated() {
            let description = "\(row.path) · \(localizedKind(row.kind).text) · \(localizedTimestamp(row.detectedAt).text)"
            let title = row.dismissed
                ? UIL("monitor.notice_dismissed_item", "{p0}（通知を閉じました）", ["p0": UIValue(description)]) : description
            let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            item.tag = index
            picker.menu?.addItem(item)
        }
        picker.selectItem(at: 0)
        picker.setAccessibilityLabel(alert.messageText)
        alert.accessoryView = picker
        alert.addButton(withTitle: UIL("monitor.detected.review", "変更内容を確認"))
        alert.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
        if alert.runModal() == .alertFirstButtonReturn, let index = picker.selectedItem?.tag, rows.indices.contains(index) {
            reviewNotice(rows[index])
        }
    }

    private func refreshStaleNotice() {
        refresh(forceNoticeRead: true)
        setActionMessage(presentationSnapshot?.reason
            ?? UIM("monitor.notice_updated", "選んだ通知は更新または解消されました。ホームの未確認件数を更新しました。"))
    }

    private func noticeFailureReason(_ object: [String: Any]?, _ raw: String) -> UIMessage {
        switch object?["result"] as? String {
        case "REFUSED_REGISTRATION": return .verbatim(raw)
        case "NOTICE_BUSY":
            return UIM("review.registration_busy", "監視が保存状態を更新中です。少し待ってから、未確認の変更をもう一度開いてください。")
        default: return reviewReason((object?["reason"] as? String) ?? String(raw.prefix(300)))
        }
    }

    private func confirmNoticeDismissal(_ row: ChangeRow, highImpact: Bool, root: String, stateDir: String) -> Bool {
        let confirm = OrchardPearlArt.makeAlert()
        let closeTitle = UIL("monitor.dismiss_notice", "通知だけ閉じる")
        confirm.messageText = closeTitle
        confirm.informativeText = UIL("monitor.dismiss_notice_explain", "通知を閉じた記録を残します。ファイルの変更と現在の監視基準を保持し、変更は未確認として残ります。「未確認の変更を確認」から開き直せます。")
        if highImpact {
            confirm.alertStyle = .warning
            confirm.informativeText = impactText("高影響な要求の要点を確認しましたか。\n\n",
                                                 "Have you reviewed the high-impact requests?\n\n") + confirm.informativeText
        }
        confirm.addButton(withTitle: closeTitle)
        let cancel = confirm.addButton(withTitle: UIL("ui.common.cancel", "キャンセル"))
        confirm.buttons[0].keyEquivalent = ""
        guard InstructionReviewModal.confirms(confirm, cancel: cancel) else { return false }
        let (status, outcome, raw) = callDetector("dismiss-notice", arguments: ["--notice-id", row.id, "--human-confirmed"],
                                                  root: root, stateDir: stateDir)
        switch outcome?["result"] as? String {
        case "DISMISSED_UNCONFIRMED" where status == 0, "ALREADY_DISMISSED" where status == 0:
            if alertRow?.id == row.id { alertPanel?.close() }
            refresh(forceNoticeRead: true)
            setActionMessage(UIM("monitor.dismiss_notice_saved", "通知を閉じました。変更は未確認として残っています。"))
        case "NOTICE_STALE":
            refreshStaleNotice()
        default:
            showResult(UIM("monitor.dismiss_notice_failed", "通知を閉じたことを保存できませんでした。\n") + noticeFailureReason(outcome, raw))
        }
        return true
    }

    @objc private func reviewItem(_ item: NSMenuItem) {
        guard let id = item.representedObject as? String else { return }
        withNoticeInteraction {
            if let row = displayedState.rows.first(where: { $0.id == id }) { reviewNotice(row) }
            else { refreshStaleNotice() }
        }
    }

    private enum InstructionDetailAction { case back, history, investigate }

    private func instructionDiff(_ diff: String) -> NSScrollView {
        let scroll = impactScroll("", height: 360)
        guard let text = scroll.documentView as? NSTextView else { return scroll }
        let colored = NSMutableAttributedString(string: "")
        for line in diff.split(separator: "\n", omittingEmptySubsequences: false) {
            let value = String(line) + "\n"
            var color = NSColor.labelColor
            var background = NSColor.clear
            if value.hasPrefix("+") && !value.hasPrefix("+++") {
                color = .systemGreen
                background = NSColor.systemGreen.withAlphaComponent(0.12)
            } else if value.hasPrefix("-") && !value.hasPrefix("---") {
                color = .systemRed
                background = NSColor.systemRed.withAlphaComponent(0.12)
            } else if value.hasPrefix("@@") {
                color = .systemBlue
            }
            colored.append(NSAttributedString(string: value, attributes: [
                .font: NSFont.monospacedSystemFont(ofSize: 12, weight: .regular),
                .foregroundColor: color, .backgroundColor: background,
            ]))
        }
        text.textStorage?.setAttributedString(colored)
        return scroll
    }

    private func showInstructionDetails(_ row: ChangeRow, review: [String: Any]?, model: MonitorImpactReview?,
                                        explanation: UIMessage?, diff: String?) -> InstructionDetailAction {
        let alert = OrchardPearlArt.makeAlert()
        alert.messageText = UIL("review.compare", "{p0} の変更内容を比較", ["p0": UIValue(row.path)])
        alert.informativeText = explanation?.text ?? impactText(
            "原文・差分と、影響を判定した根拠を確認できます。",
            "Compare original text and review the evidence for the impact assessment.")
        let tabs = NSTabView(frame: NSRect(x: 0, y: 0, width: 742, height: 397))
        func addTab(_ title: String, view: NSView) {
            let item = NSTabViewItem(identifier: nil)
            item.label = title
            item.view = view
            tabs.addTabViewItem(item)
        }
        if let diff {
            let visible = diff.isEmpty && row.kind == "ADDED"
                ? UIL("review.empty_added", "空ファイルが追加されました。現在の内容は0バイトです。") : diff
            addTab(impactText("差分", "Diff"), view: instructionDiff(visible))
        } else {
            let reason = explanation?.text ?? impactText("比較できる差分がありません。", "A verified diff is unavailable.")
            addTab(impactText("差分", "Diff"), view: impactScroll(reason))
        }
        var originals: [String] = []
        for (key, heading) in [("content", impactText("変更後の原文", "Full original text after the change")),
                               ("old_content", impactText("変更前の原文", "Full original text before the change"))] {
            guard let original = review?[key] as? String else { continue }
            let escaped = original.split(separator: "\n", omittingEmptySubsequences: false)
                .map { evidenceText(String($0)) }.joined(separator: "\n")
            originals.append(heading + "\n" + (original.isEmpty ? impactText("空（0バイト）", "Empty (0 bytes)") : escaped))
        }
        let originalText = originals.isEmpty ? impactText("照合済みの原文がありません。", "Verified original text is unavailable.")
                                             : originals.joined(separator: "\n\n")
        addTab(impactText("原文", "Originals"), view: impactScroll(originalText))
        var evidence = impactSummary(row, model, explanation)
        if let after = review?["after"] as? String {
            let before = review?["before"] as? String ?? UIL("review.no_baseline", "信頼基準の監視範囲に対象なし（追加）")
            evidence += "\n\n" + UIL("review.hash_and_colors", "基準 SHA-256: {p0}\n現在 SHA-256: {p1}\n赤は旧内容、緑は現在の内容です。承認は監視基準に反映されます。安全性は別に確認してください。",
                                     ["p0": UIValue(before), "p1": UIValue(after)])
        }
        addTab(impactText("判定根拠", "Assessment evidence"), view: impactScroll(evidence))
        alert.accessoryView = tabs
        alert.addButton(withTitle: impactText("判断へ戻る", "Return to decision"))
        alert.addButton(withTitle: UIL("monitor.history.open", "変更履歴"))
        let canInvestigate = model?.destinations.contains(where: { $0.host != nil }) ?? false
        if canInvestigate {
            alert.addButton(withTitle: impactText("送信先を調べる", "Investigate destinations"))
        }
        switch alert.runModal() {
        case .alertSecondButtonReturn: return .history
        case .alertThirdButtonReturn where canInvestigate: return .investigate
        default: return .back
        }
    }

    private func reviewNotice(_ row: ChangeRow) {
        let root = selectedRoot, stateDir = selectedStateDir
        let (status, object, raw) = callDetector("review", arguments: ["--notice-id", row.id], root: root, stateDir: stateDir)
        if object?["result"] as? String == "NOTICE_STALE" {
            refreshStaleNotice()
            return
        }
        let review = object?["notice_id"] as? String == row.id ? object : nil
        let impact = MonitorImpactReview.decode(review?["impact_review"], kind: row.kind)
        let token = review?["review_token"] as? String
        let after = review?["after"] as? String
        let before = review?["before"] as? String
        let diff = review?["diff"] as? String
        let canApprove = status == 0 && token != nil && after != nil && diff != nil && impact != nil
        let explanation: UIMessage?
        if canApprove {
            explanation = nil
        } else if status == 0 {
            explanation = UIM("impact.receipt_unverified", "変更説明のレシートを検証できません。承認は保留されます。")
        } else {
            explanation = noticeFailureReason(object, raw)
        }
        let japanese = UILanguagePreference.shared.language == .ja
        let summary = InstructionChangeSummary(review: impact, japanese: japanese)
        let blockedReason = canApprove ? "" : blockedReviewReason(explanation, result: object?["result"] as? String)
        decision: while true {
            let screen = InstructionDecisionPanel(path: row.path, filename: row.filename,
                change: localizedKind(row.kind).text, summary: summary, canApprove: canApprove,
                canDismiss: !row.dismissed, blockedReason: blockedReason, japanese: japanese)
            switch screen.runModal() {
            case .hold:
                return
            case .approve:
                if canApprove && confirmBaselineAcceptance(row) { break decision }
            case .details:
                switch showInstructionDetails(row, review: review, model: impact, explanation: explanation, diff: diff) {
                case .back: break
                case .history: browseMDHistory(root: root, stateDir: stateDir)
                case .investigate:
                    if let impact { investigateImpactDestinations(impact) }
                }
            case .dismiss:
                if !row.dismissed && confirmNoticeDismissal(row, highImpact: summary.highImpact, root: root, stateDir: stateDir) {
                    return
                }
            }
        }
        guard let token, let after else { return }

        let (acceptStatus, outcome, response) = callDetector("accept", arguments: [
            "--notice-id", row.id, "--review-token", token,
            "--reviewed-before", before ?? "NONE", "--reviewed-after", after,
            "--human-confirmed"
        ], root: root, stateDir: stateDir)
        refresh(forceNoticeRead: true)
        if acceptStatus == 0 && (outcome?["result"] as? String) == "ACCEPTED" {
            showResult(UIM("review.accepted", "承認しました: {p0}\n新しい基準: {p1}", ["p0": UIValue(row.path), "p1": UIValue(after)]))
        } else if (outcome?["result"] as? String) == "NOTICE_STALE" {
            refreshStaleNotice()
        } else {
            let reason = (outcome?["result"] as? String) ?? String(response.prefix(300))
            let explanation: UIMessage
            if reason == "REFUSED_REGISTRATION" || reason == "NOTICE_BUSY" {
                explanation = noticeFailureReason(outcome, response)
            } else if let detail = outcome?["reason"] as? String {
                explanation = reviewReason(detail)
            } else {
                explanation = acceptReason(reason)
            }
            showResult(UIM("review.diff_unavailable_prefix", "安全に差分を比較できません。承認はできません。\n理由: ") + explanation)
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        guard menu === item?.menu else { return }
        let titles = menu.items.filter { !$0.isSeparatorItem }.map(\.title)
        previewMenuEvidence?.stringValue = UIL("ui.menu.opened", "実メニューが開きました:\n") + titles.joined(separator: "\n")
    }

}

@main private enum SentinelMenuEntry {
    static func main() throws {
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--local-report-readme" {
            do {
                _ = try SentinelRuntime.load()
                print(try OrchardLocalReportStore.userLocal.dailyReadme(CommandLine.arguments[2]))
                return
            } catch {
                fputs("Local report counts unavailable.\n", stderr)
                exit(78)
            }
        }
        // Same one-shot job and presentation as the GUI; no native GO is issued.
        if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--inspect-zip" {
            do {
                let url = URL(fileURLWithPath: CommandLine.arguments[2])
                let receipt = try OrchardZipJob(url: url).run()
                let presentation = try MainActor.assumeIsolated {
                    try orchardZipPresentation(receipt: receipt, name: url.lastPathComponent)
                }
                let object: [String: Any] = [
                    "receipt": try JSONSerialization.jsonObject(with: receipt),
                    "presentation": presentation
                ]
                print(String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), as: UTF8.self))
                return
            } catch let limit as OrchardZipSizeLimit {
                fputs(limit.guidance.text + "\n", stderr)
                exit(78)
            } catch {
                fputs("ZIP inspection unavailable; result not accepted.\n", stderr)
                exit(78)
            }
        }
        let options = optionsFromArguments()
        if options.inspect {
            var monitor: [String: Any]?
            if !options.root.isEmpty && !options.stateDir.isEmpty &&
               FileManager.default.fileExists(atPath: options.stateDir + "/baseline.json") {
                monitor = nativeMonitorStatus(root: options.root, stateDir: options.stateDir)
            }
            let state = loadDisplayState(root: options.root, stateDir: options.stateDir,
                                         registrationError: options.registrationError, monitor: monitor) {
                readNoticeRows(options: options, root: options.root, stateDir: options.stateDir)
            }
            let output: [String: Any] = ["title": state.title, "menu": lines(for: state),
                                         "monitor_state": monitor?["state"] ?? NSNull(),
                                         "login_registration": MainActor.assumeIsolated { SentinelLoginService().status.rawValue },
                                         "residency_activation_build": SentinelResidencyBuild.activationAllowed,
                                         "runtime_verified": options.runtimeError == nil && options.runtimeManifestSHA256 != nil,
                                         "runtime_manifest_sha256": options.runtimeManifestSHA256 ?? NSNull(),
                                         "runtime_error": options.runtimeError ?? NSNull()]
            let data = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
            print(String(decoding: data, as: UTF8.self))
            if options.runtimeError != nil { exit(78) }
        } else {
            guard options.runtimeError == nil else {
                fputs(UIL("runtime.startup_refused", "同梱runtimeの同一性を確認できません。起動を停止しました。\n"), stderr)
                exit(78)
            }
            MainActor.assumeIsolated {
                let app = NSApplication.shared
                let delegate = MenuController(options: options)
                app.delegate = delegate
                app.run()
            }
        }
    }
}

// Presentation-only localization v1. Embedded in OrchardMain.swift so the
// existing eight-source build recipe needs no change. No execution authority.
enum UILanguage: String, CaseIterable { case ja, en }

final class UILanguagePreference: @unchecked Sendable {
    static let shared = UILanguagePreference()
    static let key = "orchard.ui.language.v1"
    private let defaults: UserDefaults
    private let lock = NSLock()
    private var selected: UILanguage
    private(set) var persistenceConfirmed = true

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        selected = (defaults.object(forKey: Self.key) as? String)
            .flatMap(UILanguage.init(rawValue:)) ?? .ja
        if selected == .en && !UILocalizationCatalog.englishReady { selected = .ja }
        // Reading an absent/invalid preference never deletes or repairs it.
    }
    var language: UILanguage { lock.lock(); defer { lock.unlock() }; return selected }
    @MainActor func choose(_ language: UILanguage) {
        guard language != .en || UILocalizationCatalog.englishReady else { return }
        lock.lock()
        let changed = selected != language
        selected = language
        lock.unlock()
        guard changed else { return }
        defaults.set(language.rawValue, forKey: Self.key)
        persistenceConfirmed = defaults.synchronize()
        // If persistence fails, the chosen session language remains visible;
        // the selector reports that relaunch persistence is unconfirmed.
    }
}

indirect enum UIValue {
    case text(String), message(UIMessage)
    init(_ value: UIMessage) { self = .message(value) }
    init<T>(_ value: T) { self = .text(String(describing: value)) }
    func render(_ language: UILanguage) -> String {
        switch self { case .text(let value): return value
        case .message(let value): return value.render(language) }
    }
}

struct UIMessage: CustomStringConvertible {
    let key: String?
    let japanese: String
    let values: [String: UIValue]
    let fragments: [UIMessage]
    init(_ key: String, _ japanese: String, _ values: [String: UIValue] = [:]) {
        self.key = key; self.japanese = japanese; self.values = values; fragments = []
    }
    private init(fragments: [UIMessage]) {
        key = nil; japanese = ""; values = [:]; self.fragments = fragments
    }
    static func verbatim(_ value: String) -> UIMessage {
        UIMessage(fragments: []).withLiteral(value)
    }
    private func withLiteral(_ value: String) -> UIMessage {
        UIMessage("__verbatim__", value)
    }
    static func + (lhs: UIMessage, rhs: UIMessage) -> UIMessage { UIMessage(fragments: [lhs, rhs]) }
    static func + (lhs: UIMessage, rhs: String) -> UIMessage { lhs + .verbatim(rhs) }
    static func + (lhs: String, rhs: UIMessage) -> UIMessage { .verbatim(lhs) + rhs }
    var text: String { render(UILanguagePreference.shared.language) }
    var raw: String { render(.ja) }
    var description: String { text }
    func render(_ language: UILanguage) -> String {
        if !fragments.isEmpty { return fragments.map { $0.render(language) }.joined() }
        guard key != "__verbatim__" else { return japanese }
        let template: String
        if language == .ja { template = japanese }
        else if let key, let entry = UILocalizationCatalog.english[key] { template = entry }
        else { return "Translation unavailable — the result and evidence remain unchanged" }
        // One pass over the template: braces in paths/evidence are never rescanned.
        let regex = try! NSRegularExpression(pattern: "\\{([A-Za-z0-9_]+)\\}")
        let source = template as NSString
        let matches = regex.matches(in: template, range: NSRange(location: 0, length: source.length))
        var output = "", cursor = 0
        for match in matches {
            output += source.substring(with: NSRange(location: cursor, length: match.range.location - cursor))
            let name = source.substring(with: match.range(at: 1))
            output += values[name]?.render(language) ?? "[translation value unavailable: \(name)]"
            cursor = NSMaxRange(match.range)
        }
        return output + source.substring(from: cursor)
    }
}
func UIM(_ key: String, _ japanese: String, _ values: [String: UIValue] = [:]) -> UIMessage {
    UIMessage(key, japanese, values)
}
func UIL(_ key: String, _ japanese: String, _ values: [String: UIValue] = [:]) -> String {
    UIM(key, japanese, values).text
}

@MainActor final class UIBindingSet {
    private var renderers: [() -> Void] = []
    func text(_ field: NSTextField, _ message: UIMessage) {
        let render = { [weak field] in
            field?.stringValue = message.text
            field?.setAccessibilityLabel(message.text)
        }
        renderers.append(render); render()
    }
    func button(_ button: NSButton, _ message: UIMessage) {
        let render = { [weak button] in
            button?.title = message.text
            button?.setAccessibilityLabel(message.text)
        }
        renderers.append(render); render()
    }
    func render() { for renderer in renderers { renderer() } }
}

enum UILocalizationCatalog {
    static let version = 1
    static let packetSHA256 = "f312eb57399bedad916bb09d0128813589fc11b474a26d87d0c308ae3fbe213d"
    static let english: [String: String] = [
        "meaning.limit.format": "Formatting changes to the same instruction are not explained as changes of meaning.",
        "meaning.limit.lines": "The line-count explanation limit was exceeded. Review the original text and diff.",
        "meaning.limit.many": "There are too many changes for a short summary.",
        "meaning.limit.multiline": "Exact correspondence between instructions cannot be established for this multi-line replacement.",
        "meaning.limit.none": "There is no explainable instruction-line change.",
        "meaning.limit.pattern": "Some changed lines do not match a supported instruction pattern.",
        "meaning.limit.unknown": "The explanation limit is not recognized. Review the original text and diff.",
        "meaning.rule.follow": "Requests that existing instructions be followed.",
        "meaning.rule.ignore": "Requests that existing instructions be ignored.",
        "meaning.rule.local_log": "Requests that a local audit log be kept.",
        "meaning.rule.no_send": "Requests that files not be sent externally.",
        "meaning.rule.send_https": "Requests that the file be sent to the HTTPS address shown in the original text.",
        "meaning.rule.unknown": "No supported rule explains this line. Review the original text and diff.",
        "meaning.scope": "Only changed lines are described. Even an explanation is not a safety verdict.",
        "meaning.summary.add": "{p0} known-instruction line(s) were added.",
        "meaning.summary.delete": "{p0} known-instruction line(s) were deleted.",
        "meaning.summary.follow_ignore": "An instruction to follow existing instructions was reversed into an instruction to ignore them.",
        "meaning.summary.ignore_follow": "An instruction to ignore existing instructions was reversed into an instruction to follow them.",
        "meaning.summary.replace": "One recognized instruction was replaced by another recognized instruction.",
        "meaning.summary.send": "An instruction requesting that a file be sent to an HTTPS address was added.",
        "meaning.unexplained": "The change was detected, but its meaning could not be explained reliably. Review the original text and diff.",
        "monitor.description": "Monitor supported AI instruction files in the selected folder. Review the explanation and diff before accepting a detected change.",
        "monitor.detected.alert": "An AI instruction file changed.",
        "monitor.detected.kind": "Change type: {kind}",
        "monitor.detected.review": "Review change",
        "monitor.detected.time": "Detected: {timestamp}",
        "monitor.detection_disclaimer": "Detecting a change is not an attack or danger verdict. Pending evidence is retained when monitoring stops or the app restarts.",
        "monitor.kind.added": "Added",
        "monitor.kind.changed": "Modified",
        "monitor.kind.deleted": "Deleted",
        "monitor.kind.other": "State changed",
        "monitor.kind.uninspectable": "Cannot compare",
        "monitor.panel_detail": "File: {p0}\nDetected: {p1}\nChange type: {p2}\n\nThe file changes remain when you close the notification.",
        "monitor.panel_title": "Orchard Sentinel — Change detected",
        "monitor.pending.count": "{p0} · Pending changes: {p1}",
        "monitor.pending.no_auto_accept": "Changes are not accepted or restored automatically.",
        "monitor.pending.none": "No pending changes.",
        "monitor.pending.remain": "Pending changes remain.",
        "monitor.phase.running": "Monitoring",
        "monitor.phase.stopped": "Stopped",
        "monitor.reason.baseline_missing": "Trusted baseline missing. Verify the original state location. State is not automatically reinitialized.",
        "monitor.reason.change": "Change record format is invalid",
        "monitor.reason.generic": "The monitor state could not be verified. Monitoring is not claimed to be running; existing evidence is retained.",
        "monitor.reason.not_running": "Monitor process running state could not be verified",
        "monitor.reason.other_active": "Another or older Orchard is monitoring. Stop it and quit, then recheck registration. Parallel monitoring is not started.",
        "monitor.reason.pending": "Pending-change format is invalid",
        "monitor.reason.pending_cap": "Pending-change count exceeds the limit",
        "monitor.reason.root": "Monitored folder does not match the baseline",
        "monitor.reason.unreadable": "Monitor process state could not be read",
        "monitor.recovery_failed": "Automatic recovery could not be attempted. Retries are bounded. Pending evidence is retained.",
        "monitor.recovery_stopped": "Automatic recovery stopped. Select resume monitoring manually. Pending changes are retained.",
        "monitor.recovery_suppressed": "Automatic recovery stopped. Pending changes are retained.",
        "monitor.recovery_unknown": "Recovery decision could not be verified. Automatic recovery is stopped; pending changes are retained.",
        "monitor.register": "Choose a folder to monitor…",
        "monitor.register_again": "Recheck registration",
        "monitor.registration_issue": "Review registration issue",
        "monitor.check_status": "Check monitor status",
        "monitor.register_first": "After registering a folder, explicitly start monitoring.",
        "monitor.register_other": "Review another registration",
        "monitor.review_pending": "Review pending changes",
        "monitor.history.open": "Change history",
        "monitor.notice_unverified": "Could not read the pending ledger. Check the monitoring status again.",
        "monitor.notice_dismissed_count": "Pending changes with notifications dismissed: {p0}",
        "monitor.notice_dismissed_item": "{p0} (notification dismissed)",
        "monitor.notice_back": "Back",
        "monitor.notice_updated": "The selected notification was updated or resolved. The home count has been refreshed.",
        "monitor.dismiss_notice": "Close notification only",
        "monitor.dismiss_notice_explain": "Orchard records that you closed the notification. The file and monitoring baseline stay as they are, and the change remains pending. Reopen it from Review pending changes.",
        "monitor.dismiss_notice_saved": "Notification dismissed. The change remains pending.",
        "monitor.dismiss_notice_failed": "Could not save the notification dismissal.\n",
        "impact.receipt_unverified": "The change explanation receipt could not be verified. Approval is on hold.",
        "monitor.root": "Monitored folder: {p0}",
        "monitor.root.check": "Monitored folder: Registration requires verification",
        "monitor.root.none": "Monitored folder: Not registered",
        "monitor.root_prefix": "Monitored folder: ",
        "monitor.running.notice": "Monitoring. A notification will appear when a supported file changes.",
        "monitor.start": "Start monitoring",
        "monitor.start_failed": "Monitor process could not start. Pending evidence is retained.",
        "monitor.start_save_failed": "Start-monitoring preference could not be saved. Monitoring was not started.",
        "monitor.starting": "Verifying that the monitor has started…",
        "monitor.state.pending": "🍎🔴 {p0} change(s) need review",
        "monitor.state.stopped": "🍎⏸ Stopped",
        "monitor.state.stopped_pending": "🍎⏸🔴 Stopped · {p0} pending",
        "monitor.state.unknown": "🍎⚠️ Status unknown",
        "monitor.state.unknown_pending": "🍎⚠️🔴 Status unknown · {p0} pending",
        "monitor.state.unregistered": "🍎⏸ Not registered",
        "monitor.state.verify_registration": "🍎⚠️ Verify registration",
        "monitor.state.watching": "🍎 Watching",
        "monitor.stop": "Stop monitoring",
        "monitor.stop_requested": "Monitoring stop requested. Pending evidence is retained.",
        "monitor.stop_save_failed": "Stop-monitoring preference could not be saved. Verify the actual state.",
        "monitor.stop_unverified": "Monitoring stop could not be verified. Recheck the actual state.",
        "monitor.stopped_after": "Project registered. Monitoring is stopped.",
        "monitor.time_missing": "Detection time not recorded (older state)",
        "monitor.title": "AI instruction file monitoring",
        "monitor.unknown.count": "Status unknown · Pending changes: {p0}",
        "monitor.unknown.no_running_claim": "Monitoring is not claimed to be running.",
        "monitor.unknown.not_unregistered": "Registration and pending count could not be verified; this is not treated as an unregistered project.",
        "monitor.unregistered.detail": "Stopped · no project registered.",
        "monitor.unregistered.no_baseline": "Monitoring and baseline creation do not occur before registration.",
        "quit.confirm": "Stop monitoring and quit Orchard?",
        "quit.consequences": "Monitoring stops. Pending changes, original content and history are retained; this does not unregister a login item.",
        "quit.full_consequences": "Automatic monitoring stays stopped after quitting and the next login until explicitly resumed. Login registration remains. Pending changes, original text and history are retained. Removing login registration is a separate action.",
        "quit.save_failed": "Quit preference could not be saved. Orchard will not quit because automatic recovery could not be suppressed.",
        "quit.stop_and_quit": "Stop monitoring and quit",
        "registration.adopt_confirm": "Review and adopt registration",
        "registration.adopt_detail": "\nPending changes: {p0}. Reference the original state location; no change is accepted, moved or deleted. Start monitoring manually.",
        "registration.adopt_explain": "Reference the existing state location. Pending changes and history remain; no change is accepted, moved or deleted. Start monitoring manually.",
        "registration.adopt_prefix": "This registration uses a different location from the released version.\nProject: ",
        "registration.adopt_question": "Adopt the discovered registration?",
        "registration.ask": "Register this project?",
        "registration.changed": "Content changed before registration or baseline creation failed. Review again.",
        "registration.confirm": "I reviewed the content — register project",
        "registration.content": "\nFile: {p0}\nSHA-256: {p1}\n--- Original content ---\n{p2}\n--- End original content ---",
        "registration.explain": "Review current content before registering. It becomes the baseline. Monitoring remains stopped after registration.",
        "registration.files": "Watched files: {p0}",
        "registration.folder_contains_state": "Choose a folder that does not contain Orchard's registration storage.",
        "registration.generic_hold": "Registration requires verification. Existing records are retained; monitoring is not started automatically.",
        "registration.helper_invalid": "Bundled registration verification could not be verified. Existing registration was not changed.",
        "registration.helper_missing_path": "Registration verification returned no state location. Existing records are retained.",
        "registration.helper_result": "Registration verification result could not be verified. Existing records are retained.",
        "registration.helper_start": "Registration verification could not start. Existing records are retained.",
        "registration.invalid_pending": "Pending-change format is invalid.",
        "registration.missing_baseline": "Trusted baseline missing. State is not automatically reinitialized.",
        "registration.no_files": "No supported instruction files are present. Future additions will be monitored after monitoring is started.",
        "registration.notice.current": "Saved registration verified. Start monitoring manually.",
        "registration.notice.preview": "Adopted the reviewed registration. Original state location and pending changes are retained. Start monitoring manually.",
        "registration.notice.r2": "Adopted the released registration. Pending changes and acceptance history remain at the original location. Start monitoring manually.",
        "registration.old_active": "Another or older Orchard is monitoring. Stop it first; parallel monitoring is not started.",
        "registration.original": "Original content",
        "registration.pick": "Explicitly select the project folder to monitor.",
        "registration.pointer_failed": "The created baseline is retained. Saving the registration could not be verified.",
        "registration.preview_incomplete": "Registration preview is incomplete. Project was not registered.",
        "registration.preview_unavailable": "Instruction files cannot be listed safely. Project was not registered.",
        "registration.project": "Project: {p0}",
        "registration.reason.accept": "An interrupted acceptance record exists. Check and quit the older version. Pending changes are not accepted or reinitialized automatically.",
        "registration.reason.busy": "Another or older Orchard is updating saved state. Recheck registration after it finishes.",
        "registration.reason.changed": "Registration changed during confirmation. Existing registration is retained; review it again.",
        "registration.reason.choice": "A previous registration was found at another location. Review it explicitly before adopting it; it is separate from the released registration.",
        "registration.reason.invalid": "Registration format could not be verified. Check the older registration and state location; retain the original files.",
        "registration.reason.io": "Registration could not be read safely. Existing records are retained. Check the state location and recheck registration.",
        "registration.reason.monitor": "Previous monitor state could not be verified. Check and quit the older monitor, then recheck registration.",
        "registration.reason.path": "Registration or state path, ownership or permissions could not be verified. Check the old state location and retain original records.",
        "registration.reason.directory_permissions": "Orchard could not verify permissions for the registration folder or its parent. Keep the original files and check ownership and access in Finder.",
        "registration.reason.running": "Another or older Orchard is monitoring. Stop it and quit, then recheck registration. Parallel monitoring is not started.",
        "registration.reason.state": "Baseline, pending changes or acceptance history are incompatible or unverified. Check saved state in the older version; no automatic reinitialization.",
        "registration.runtime_invalid": "Bundled runtime identity could not be verified. Startup is stopped.",
        "registration.state_unverified": "Registration or saved state could not be verified. Records are retained.",
        "registration.switch.action": "Change monitored folder",
        "registration.switch.ask": "Register this folder as the new monitoring target?",
        "registration.switch.done": "Monitored folder changed. Previous monitoring records were kept. Monitoring is stopped for the new folder.",
        "registration.switch.evidence": "Orchard could not save the original text and diffs for the previous folder's pending changes. The previous registration and records were kept. Review the pending changes and try again.",
        "registration.switch.pick": "Select the new folder to monitor.",
        "registration.switch.review": "Monitoring is stopped. Review the instruction files for the new folder.",
        "registration.switch.same": "This is the current monitored folder. Select a different folder.",
        "registration.switch.stop_confirm": "Stop monitoring and continue",
        "registration.switch.stop_explain": "Orchard will stop monitoring before showing the new folder’s instruction files. Previous monitoring records are kept. If you cancel registration afterward, you’ll need to start monitoring manually.",
        "registration.switch.stop_failed": "Orchard could not verify a clean monitor exit. The registered folder was left in place.",
        "registration.switch.stop_question": "Stop monitoring and change the monitored folder?",
        "registration.switch.stopping": "Waiting for the current monitor to stop.",
        "registration.switch.unverified": "The folder switch could not be verified. Leave monitoring stopped and recheck the saved registration.",
        "registration.timeout_prefix": "Registration verification timed out (",
        "registration.timeout_suffix": "). Existing records are retained. Quit Orchard and contact support.",
        "registration.unreadable": "Saved state cannot be read.",
        "report.counts": "Outer ZIP entries {p0} / text files read {p1} / text bytes read {p2}",
        "report.decision": "Human decision: {p0}",
        "report.finding": "Untrusted data / {p0} / {p1}:{p2} / {p3} / {p4}",
        "report.findings": "Findings: {p0}",
        "report.gate": "Inspection gate: {p0} (not permission to open)",
        "report.handoff": "Gate before AI handoff: HOLD",
        "report.input_sha": "Input SHA256: {p0}",
        "report.inspection_status": "Inspection status: {p0}",
        "report.instruction_status": "Instruction inspection: {p0}",
        "report.limit_prefix": "Limitation: ",
        "report.limits": "Scope and limitations:",
        "report.mock": "Simulated output: {p0} (no real folder or AI handoff)",
        "report.scope": "Inspection scope: {p0}",
        "report.sha_unknown": "SHA inspection: unavailable",
        "report.unknown_count": "UNKNOWN conditions: {p0}",
        "report.untrusted": "All ZIP text is untrusted data, not instructions or approval for an AI.",
        "report.worker_invalid": "Worker/result not qualified: {p0}",
        "residency.change_disabled": "OS registration changes are disabled in this build. Use Stop monitoring to stop the current monitor.",
        "residency.disable_confirm": "Remove registration and stop monitoring",
        "residency.disable_consequences": "Stop automatic monitoring and recovery at the next login. Pending changes, original text and acceptance history are not deleted. If removal fails, show the actual macOS registration state.",
        "residency.disable_incomplete": "Removal or saving is incomplete. ",
        "residency.disable_question": "Remove login registration and stop monitoring?",
        "residency.disable_saved": "Removal response and the saved stop preference were verified. ",
        "residency.disable_status": "macOS login item: {p0}. {p1}Monitor stop is verified separately using its lease and scan. Pending changes are retained.",
        "residency.disabled_candidate": "Login monitoring is an inactive candidate gated separately. No macOS login item is changed.",
        "residency.enable_confirm": "I reviewed the explanation — enable",
        "residency.enable_consequences": "Monitor the selected project after the next login, with bounded crash recovery. Changes are not accepted, files are not executed or sent externally. Pending changes remain after stopping or quitting. Login-item removal is separate. macOS approval may be required. This candidate is disabled in this build.",
        "residency.enable_question": "Enable monitoring at login?",
        "residency.identity_invalid": "Login-monitoring registration or app identity could not be verified. No registration is performed.",
        "residency.login_choice": "Saved login preference: {p0}",
        "residency.login_detail": "Login monitoring: disabled in this build",
        "residency.login_disabled": "Automatic launch at login is disabled in this build.",
        "residency.login_status": "Automatic launch at login: disabled in this build",
        "residency.menu.disable": "Remove login registration and stop monitoring… (disabled)",
        "residency.menu.enable": "Enable login monitoring… (disabled in this build)",
        "residency.monitor_choice": "Saved automatic-monitoring preference: {p0}",
        "residency.os_line": "Login item (macOS): {p0}",
        "residency.os_status": "macOS login item: {p0}. Registration alone does not prove monitoring is running.",
        "residency.pause_reason": "Reason for monitoring pause/recovery suppression: {reason}",
        "residency.precheck_failed": "Explicit selection or trusted baseline could not be verified. No registration is performed.",
        "residency.reason.clock": "Automatic recovery stopped because time could not be verified",
        "residency.reason.crash": "Automatic recovery stopped after repeated crashes",
        "residency.reason.disable": "User selected login-item removal",
        "residency.reason.explicit": "Explicit user selection saved (not proof of running state)",
        "residency.reason.invalid": "Stopped because saved state could not be verified",
        "residency.reason.off": "Login monitoring not selected",
        "residency.reason.os": "Automatic monitoring stopped because macOS registration is not enabled",
        "residency.reason.pause": "Monitoring stopped by the user",
        "residency.reason.quit": "User stopped monitoring and quit",
        "residency.reason_line": "Automatic-monitoring reason: {p0}",
        "residency.register_failed": "Login registration could not complete. macOS state: {p0}. Saved preference and actual registration are separate.",
        "residency.registered_not_running": "A registered login item does not prove monitoring is running.",
        "residency.status.approval": "Awaiting macOS approval",
        "residency.status.enabled": "Registered (launch eligible; does not prove monitoring is running)",
        "residency.status.not_found": "Service not found",
        "residency.status.unregistered": "Not registered",
        "review.accept": "I reviewed this change — accept it as the new baseline",
        "review.accept_changed": "Content changed during acceptance. Pending evidence is retained.",
        "review.accept_failed": "Acceptance failed. Review the pending state and history.",
        "review.accept_precheck_failed": "The target could not be safely rechecked immediately before acceptance. Pending evidence is retained.",
        "review.accepted": "Change accepted: {p0}\nNew baseline: {p1}",
        "review.after": "After (changed instruction lines)",
        "review.baseline_hash": "Baseline SHA-256: {before}",
        "review.before": "Before (changed instruction lines)",
        "review.compare": "Compare changes in {p0}",
        "review.current_hash": "Current SHA-256: {after}",
        "review.diff_absence": "The saved baseline does not establish that this file was absent. Keep the existing records and recheck the registration and baseline.",
        "review.diff_changed": "Target has changed since detection. Review after redetection.",
        "review.diff_deleted": "A deleted file has no current text to approve. Its deletion remains pending.",
        "review.diff_colors": "Red shows previous content; green shows current content. Change detection is not a danger verdict.",
        "review.diff_hash_mismatch": "Previous saved content does not match the trusted baseline hash.",
        "review.diff_incomplete": "The current scan did not finish reading the monitored instruction files. Check folder access and scan coverage, then review after redetection.",
        "review.diff_limit": "Diff exceeds the display limit.",
        "review.diff_old_missing": "Trusted previous content was not saved; a safe diff is unavailable.",
        "review.diff_size": "Target exceeds the 64 KiB comparison limit.",
        "review.diff_state": "The saved baseline and detection records could not be verified together. Keep the existing records and recheck the registration.",
        "review.diff_unavailable": "The diff cannot be compared safely; acceptance is unavailable. Reason: {reason}",
        "review.diff_unavailable_prefix": "The diff cannot be compared safely; acceptance is unavailable.\nReason: ",
        "review.diff_unknown": "Saved state or target cannot be compared safely; review after redetection.",
        "review.diff_unsafe": "The target is not a readable regular file. Check its file type and read access, then review after redetection.",
        "review.diff_utf8": "Target cannot be safely displayed as UTF-8 text.",
        "review.explanation": "Explanation: {p0}",
        "review.explanation_not_verdict": "This describes the detected change; it does not determine whether it is safe or an attack.",
        "review.empty_added": "An empty file was added. Its current content is 0 bytes.",
        "review.hash_and_colors": "Baseline SHA-256: {p0}\nCurrent SHA-256: {p1}\nRed shows previous content. Green shows current content. Approval updates the monitoring baseline. Assess safety separately.",
        "review.meaning_inconsistent": "Explanation and supporting lines do not agree; acceptance is unavailable.",
        "review.meaning_missing": "Explanation evidence is incomplete; acceptance is unavailable.",
        "review.no_baseline": "Absent from the trusted monitored baseline (new file)",
        "review.no_changed_lines": "(No changed lines on this side)",
        "review.original_line": "Line {p0} · Original: {p1}",
        "review.pending_cancel": "Canceling leaves pending evidence intact.",
        "review.registration_busy": "The monitor is updating saved state. Wait a moment, then open the pending change again.",
        "review.rejected": "Change acceptance refused: {p0}\n{p1}\nResult code: {p2}",
        "review.review_changed": "The content or detection state changed after review. Review again.",
        "review.title": "Review instruction changes in {p0}",
        "review.unexplained_reasons": "Reasons the change could not be explained",
        "review.unexplained_reasons_heading": "Reasons the change could not be explained\n",
        "review.view_original_diff_sha": "Review original text, diff, and SHA-256",
        "runtime.debug": "Manual debug configuration (bundled identity not verified)",
        "runtime.invalid": "Bundled runtime identity could not be verified. Substituting an external Python is not allowed in this package.",
        "runtime.line": "Runtime: {p0}",
        "runtime.startup_refused": "Bundled runtime identity could not be verified. Startup is stopped.\n",
        "runtime.verified": "Bundled runtime identity verified at startup (publisher trust is separate)",
        "sha.coverage": "ZIP matching coverage: {p0} files checked · {p1} uninspectable · {p2} matches",
        "sha.db.clock": "Database: time cannot be verified. Nonmatches are held.",
        "sha.db.failed": "Database: update failed. Existing known matches remain; nonmatches are held.",
        "sha.db.ready": "Database: stored snapshot used; within 25 hours (age is advisory).",
        "sha.db.stale": "Database: older than 25 hours (advisory); stored snapshot matching remains available.",
        "sha.db_composition": "Retained 100,000 previous values + 200,000 new = 300,000 distinct stored SHA values.",
        "sha.db_coverage_limit": "Limited coverage: not a complete history, not the newest 300,000, and not a broad malware-detection guarantee.",
        "sha.db_unverified": "Database freshness not verified; a nonmatch cannot be concluded.",
        "sha.full_generated": "Full snapshot generated (UTC): {p0}",
        "sha.full_limits": "Full: 1,173,888 rows validated. Total distinct Full values and first-seen periods of stored values are not established.",
        "sha.full_retrieved": "Full retrieved (UTC): {p0}",
        "sha.label": "ZIP SHA-256 inspection: {p0}",
        "sha.latest_retrieval": "Latest retrieval: {p0} / {p1}",
        "sha.match": "Match in stored real SHA values (not a safety verdict).",
        "sha.mode.age_test": "[TEST MODE] Simulated clock age beyond 25 hours; the actual clock and database were not changed.",
        "sha.mode.failed_test": "[TEST MODE] Simulated update-failure display; no actual retrieval failure occurred.",
        "sha.mode.normal": "Normal inspection: evaluated using the Mac's current time.",
        "sha.next_check": "Next suggested check (UTC): {p0} (once daily). Automatic updates are disabled.",
        "sha.no_execute": "No match is not evidence of safety or permission to open or execute.",
        "sha.no_match": "No match in covered database (does not mean safe).",
        "sha.oldest_source": "Oldest retained source generation (UTC): {p0}",
        "sha.recent_composition": "Recent: 1,172 values (116 already stored; 1,056 new) + 198,944 new values from Full.",
        "sha.recent_times": "Latest Recent generated / retrieved (UTC): {p0} / {p1}",
        "sha.retained_absent": "Eight previously stored values were absent from this Full snapshot and are retained. Absence alone is not a removal request.",
        "sha.retrieval": "Retrieved (UTC): {p0} · SHA values stored: {p1}",
        "sha.self_check": "Internal stored-value self-check: {p0}/{p1}",
        "sha.self_check_detail": "Internal self-check is not a positive detection in a ZIP. Real stored SHA values are not displayed or exported.",
        "sha.self_check_not_detection": "Internal self-check is not a positive detection in a malicious ZIP.",
        "sha.source": "Source: {url} · {attribution}",
        "sha.source_recent": "Declared recent-source coverage: {p0} to {p1} (48 hours)",
        "sha.source_url": "Source: {p0}",
        "sha.uninspectable": "Some items could not be matched.",
        "sha.update_off": "Automatic updates are disabled.",
        "sha.update_status": "Latest retrieval: {status}",
        "ui.bullet": "•",
        "ui.common.cancel": "Cancel",
        "ui.common.close": "Close",
        "ui.common.details": "Details: {reason}",
        "ui.common.file": "File: {p0}",
        "ui.common.later": "Later",
        "ui.common.not_verified": "Not verified",
        "ui.header.build": "Orchard 0.4 · build12 · 300,000 stored SHA values · No automatic updates · Login monitoring disabled",
        "ui.header.subtitle": "Inspect ZIP files. Notice changes to AI instruction files.",
        "ui.language.en": "English",
        "ui.language.ja": "日本語",
        "ui.language.label": "Language / 言語",
        "ui.language.save_unverified": "Display language changed for this session; persistence after relaunch could not be confirmed.",
        "ui.menu.copy": "Copy",
        "ui.menu.edit": "Edit",
        "ui.menu.open": "Open Orchard",
        "ui.menu.opened": "Actual menu opened:\n",
        "ui.menu.quit": "Quit Orchard",
        "ui.menu.select_all": "Select All",
        "ui.translation.defect": "English presentation is inconsistent. Acceptance presentation is held until the localization defect is corrected.",
        "ui.value.failure": "Failed",
        "ui.value.off": "Off",
        "ui.value.on": "On",
        "ui.value.stopped": "Stopped",
        "ui.value.success": "Success",
        "zip.abort": "Inspection canceled.",
        "zip.baseline.full": "Stored, limited set of 300,000 distinct SHA values: 100,000 retained + 200,000 new.\n\nNot the newest 300,000 or a complete history. No match does not mean safe or authorized to open or execute.\n\nSource generation and retrieval times are shown. Stored snapshot matching remains available beyond 25 hours; integrity failures, uninspectable results or permission withdrawal still cause HOLD.\n\nUpdates preserve compatible registration and pending changes. An older active monitor causes HOLD. One folder can be registered; start monitoring manually after registration. Automatic updates and login registration are disabled.",
        "zip.baseline.limits": "Show source/retrieval times. Age beyond 25 hours alone does not stop stored matching; integrity failures, uninspectable results, or permission withdrawal still cause HOLD.",
        "zip.baseline.monitor": "One registered folder; monitoring starts manually. Automatic updates and login registration are disabled.",
        "zip.baseline.scope": "Stored, limited set of 300,000 distinct SHA values; not the newest 300,000 or a complete history. No match does not mean safe or authorized to open or execute.",
        "zip.bounds": "ZIP limits are {p0} MiB and 1,024 entries, with 64 MiB total uncompressed. The inspection worker stops after at most 10 seconds.",
        "zip.cancel": "Cancel inspection",
        "zip.cancel_wait": "Canceling and confirming that the worker process has exited…",
        "zip.description": "Check outer ZIP structure, known hashes, and text. Inspect supported inner ZIP text one level deep. The app does not extract files to disk, execute them, or send them over the network.",
        "zip.discarded": "No inspection result was accepted.",
        "zip.failure_prefix": "ZIP limits, input stability, runtime or result could not be verified.\nThis is not a safety finding or a confirmed nonmatch.\nDetails: ",
        "zip.failure_reason": "ZIP limits, input stability, runtime, or the result could not be verified. This is not a safety finding or a confirmed nonmatch. Details: {reason}",
        "zip.inspect_selected": "Inspect this ZIP",
        "zip.inspecting": "Inspecting: {filename}",
        "zip.inspecting_prefix": "Inspecting: ",
        "zip.instruction.detected": "Potentially suspicious instructions detected",
        "zip.instruction.in_progress": "Inspecting instructions…",
        "zip.instruction.incomplete": "Instruction inspection could not be completed.",
        "zip.instruction.not_detected": "No suspicious instructions detected by the supported rules. This does not prove the ZIP is safe.",
        "zip.instruction.not_started": "Instruction inspection has not started.",
        "zip.instruction.zero.unsupported": "No readable text for instruction inspection was found in the ZIP.",
        "zip.instruction.zero.encoding": "Orchard could not confirm the text encoding of the documents.",
        "zip.instruction.zero.size": "The supported documents exceeded the size limit for instruction inspection.",
        "zip.instruction.zero.unreadable": "No documents could be read for instruction inspection. See the inspection details for the reason.",
        "zip.home.title": "Check a ZIP before sharing it with AI",
        "zip.home.scope": "Inspection scope",
        "zip.not_selected": "No ZIP selected yet.",
        "zip.quit_wait": "Canceling inspection and waiting for the worker to exit before quitting.",
        "zip.repeat": "Inspect again (normal mode)",
        "zip.report.details": "Inspection details:",
        "zip.report.github.action": "Report on GitHub",
        "zip.report.github.title": "Review the summary before sharing",
        "zip.report.github.instructions": "Issues are public. Copy the summary, sign in to GitHub, and paste it into the form. Submit it yourself when ready. The summary omits the ZIP, document text, file paths, and SHA-256.",
        "zip.report.github.summary": "Orchard detected potentially suspicious instructions (unverified).",
        "zip.report.github.copy": "Copy summary",
        "zip.report.github.copied": "Summary copied.",
        "zip.report.github.copyFailed": "The summary could not be copied.",
        "zip.report.github.open": "Open GitHub form",
        "zip.report.github.openFailed": "The GitHub form could not be opened.",
        "zip.report.github.browser": "Review the summary in your browser and submit it on GitHub.",
        "zip.report.github.stale": "This result expired or changed. Inspect the ZIP again.",
        "zip.report.approveLocal": "Approve local report",
        "zip.report.accepted": "Recorded on this Mac as an unverified report.",
        "zip.report.cancelled": "Cancelled. No report was recorded.",
        "zip.report.checkReceipt": "Check local receipt",
        "zip.report.duplicate": "The same content is already recorded. No new report was added.",
        "zip.report.localOnly": "Approval records an unverified report on this Mac only. Nothing is sent.",
        "zip.report.payloadClass": "Classification  Suspected instructions",
        "zip.report.payloadPrivacy": "The report content excludes the ZIP itself, file paths, document text and user identifiers.",
        "zip.report.payloadRules": "Finding categories  {p0}",
        "zip.report.payloadSHA": "ZIP SHA-256  {p0}",
        "zip.report.payloadVersion": "Inspection version  {p0}",
        "zip.report.preview": "Review report details",
        "zip.report.readBack": "Confirmed the local unverified receipt.",
        "zip.report.saveLocal": "Approve and record locally",
        "zip.report.savedFixture": "Saved synthetic finding. Approval records it in the local test intake.",
        "zip.report.stale": "This result is no longer eligible for recording. Inspect the ZIP again.",
        "zip.report.unresolved": "The outcome is unknown. You can check the local receipt. There is no automatic retry.",
        "zip.report.simulation": "[TEST MODE]",
        "zip.pearl.archiveSize": "Input size: {p0} bytes",
        "zip.pearl.collapse": "Close details",
        "zip.pearl.evidence": "Evidence details",
        "zip.pearl.fileTitle": "ZIP file inspected",
        "zip.pearl.findingLine": "  {p0} · line {p1}",
        "zip.pearl.findings": "Flagged entries: {p0} · Findings: {p1}",
        "zip.pearl.foundScoped": "The selected text and covered database were checked.",
        "zip.pearl.foundTitle": "What was found",
        "zip.pearl.guidance": "Findings and next steps",
        "zip.action.guidance": "Guidance by action",
        "zip.action.mac.title": "Extract or view on Mac",
        "zip.action.mac.checked": "Outer ZIP structure checked statically.",
        "zip.action.mac.incomplete": "Static ZIP structure check incomplete.",
        "zip.action.mac.unrecorded": "No outer ZIP structure result recorded.",
        "zip.action.mac.limit": "Extraction and viewing safety is unverified.",
        "zip.action.mac.shaPause": "Hold off opening the matching files.",
        "zip.action.ai.title": "Share with AI",
        "zip.action.ai.checked": "No findings in {p0} checked documents.",
        "zip.action.ai.incomplete": "Document check incomplete ({p0} read).",
        "zip.action.ai.detected": "Suspicious instructions detected ({p0}).",
        "zip.action.ai.noTargets": "No instruction documents in scope.",
        "zip.action.ai.excludedFormats": "{p0} excluded ({p1})",
        "zip.action.ai.excluded": "{p0} excluded",
        "zip.action.ai.archiveUnread": "Archive-level check incomplete",
        "zip.action.ai.unread": "{p0} unchecked",
        "zip.action.ai.bodyUnread": "Instruction text unscanned in {p0}",
        "zip.action.ai.displayUnverified": "Visual interpretation unverified in {p0}",
        "zip.scope.backspaceDisplay": "Instruction text was scanned. U+0008 leaves its visual interpretation unverified.",
        "zip.action.ai.defer": "Hold off sharing. See Review details.",
        "zip.action.ai.source": "Check the sender and purpose before sharing.",
        "zip.action.decision.doNotShare": "Do not share (a finding was detected)",
        "zip.action.decision.uncheckedItems": "{p0} potential instruction items",
        "zip.action.decision.uncheckedArchive": "Part of the instruction scope",
        "zip.action.decision.thoroughChoice": "{p0} still unchecked. Hold off sharing with AI and choose [Inspect further].",
        "zip.action.decision.informChoice": "{p0} still unchecked. Hold off sharing with AI and choose [Review details] to see why.",
        "zip.action.decision.zeroThorough": "No text inspected ({p0}). Hold off sharing with AI and choose [Inspect further].",
        "zip.action.decision.zeroHold": "No text inspected ({p0}). Hold off sharing with AI and choose [Review details] to see the affected files.",
        "zip.failure.archiveTooLarge": "The {p0}-byte ZIP exceeds the {p1} MiB input limit. Its text was not inspected. Hold off sharing with AI. To inspect another ZIP, select one within the limit.",
        "zip.thorough.button": "Inspect further",
        "zip.thorough.running": "Inspecting with more time, size and depth. Compression ratio checks remain active.",
        "zip.thorough.inProgress": "Additional inspection in progress",
        "zip.thorough.knownProgress": "Inspecting {p0} previously unchecked items ({p1} remaining)",
        "zip.thorough.cancel": "Cancel inspection",
        "zip.thorough.stopping": "Cancelling additional inspection",
        "zip.thorough.stopped": "Additional inspection cancelled. Showing the previous result.",
        "zip.thorough.failed": "Additional inspection failed. Showing the previous result.",
        "zip.thorough.cleanupUnverified": "The inspection process could not be confirmed stopped.",
        "zip.action.ai.encrypted": "The risk of instructions being read is low while encrypted. Decrypted contents remain unchecked.",
        "zip.action.ai.moreFindings": "There are more findings than the list can display.",
        "zip.action.format.opaque": "Binary files",
        "zip.action.format.encrypted": "Encrypted",
        "zip.scope.reason.opaqueOutOfScope": "Unidentified binary (outside scope)",
        "zip.scope.reason.encryptedOutOfScope": "The content cannot be read while encrypted",
        "zip.scope.reason.pdfUnchecked": "PDF and similar document bodies remain unchecked",
        "zip.scope.reason.unhandledArchive": "The contents of this archive format remain unchecked",
        "zip.scope.reason.streamStructure": "Tar or gzip structure or integrity anomaly",
        "zip.scope.reason.thoroughDepth": "Nested archive depth limit (four inner levels)",
        "zip.scope.reason.thoroughArchiveSize": "Nested archive body limit (16 MiB each)",
        "zip.scope.reason.thoroughReadBudget": "Shared decompression and read budget (128 MiB)",
        "zip.scope.reason.thoroughTotalSize": "Declared uncompressed size exceeds 128 MiB",
        "zip.scope.reason.thoroughTextSize": "Instruction document body limit (16 MiB each)",
        "zip.scope.reason.thoroughTextTotal": "Instruction document read budget (64 MiB total)",
        "zip.scope.reason.thoroughMemberSize": "Uncompressed member limit (32 MiB)",
        "zip.scope.reason.thoroughDirectory": "ZIP central directory limit (2 MiB)",
        "zip.scope.reason.thoroughEntryLimit": "ZIP entry count limit (4,096 entries)",
        "zip.scope.reason.thoroughInnerDirectory": "Shared archive directory budget (4,096 entries and 2 MiB)",
        "zip.action.evidence.item": "{p0} · {p1}",
        "zip.action.evidence.finding": "{p0} · line {p1} · {p2}",
        "zip.action.ai.shaUnchecked": "{p0} items without a known-SHA check (separate check)",
        "zip.action.ai.staticFinding": "A static rule matched. Context and intent remain undetermined.",
        "zip.action.mac.structurePause": "Hold off extracting the ZIP because of a structural anomaly.",
        "zip.action.format.sqlite": "SQLite",
        "zip.action.format.internalLinks": "In-ZIP links",
        "zip.scope.reason.sqlite": "SQLite database contents are outside scope",
        "zip.scope.reason.internalLink": "Link points within the ZIP",
        "zip.scope.reason.externalLink": "Link points outside the ZIP",
        "zip.scope.reason.linkCycle": "Link references form a cycle",
        "zip.scope.reason.linkConflict": "Link path conflicts with a directory",
        "zip.scope.reason.linkUnresolved": "Link target could not be matched to a ZIP entry",
        "zip.scope.reason.linkInvalid": "The stored link target is invalid",
        "zip.scope.reason.linkSize": "Link target size limit (512 bytes)",
        "zip.scope.reason.linkChain": "Link chain limit (16 references)",
        "zip.scope.reason.innerDepthLimit": "Nested archive depth limit (one inner level)",
        "zip.scope.reason.textMemberLimit": "Instruction document size limit (4 MiB per document)",
        "zip.scope.reason.textTotalLimit": "Shared instruction text budget (32 MiB total)",
        "zip.scope.reason.memberSizeLimit": "Uncompressed member size limit (16 MiB)",
        "zip.scope.reason.ratioLimit": "Expansion ratio limit (100×)",
        "zip.scope.reason.entryLimit": "ZIP entry count limit (1,024 entries)",
        "zip.scope.reason.directoryLimit": "ZIP central directory size limit (1 MiB)",
        "zip.scope.reason.innerDirectoryLimit": "Shared outer and nested ZIP directory budget (1,024 entries and 1 MiB)",
        "zip.scope.reason.pathLimit": "Path size limit (512 bytes; excess is omitted)",
        "zip.scope.reason.archiveSizeLimit": "ZIP file size limit",
        "zip.action.format.pdf": "PDF",
        "zip.action.format.executable": "executables",
        "zip.action.format.archive": "unsupported archives",
        "zip.action.format.assets": "non-text items",
        "zip.action.run.title": "Run a program",
        "zip.action.run.limit": "Execution safety is untested.",
        "zip.action.run.mint": "Mint covers the document check only. Verify safety before running.",
        "zip.action.run.shaPause": "Hold off running the matching files.",
        "zip.pearl.hold": "Inspection status: on hold (HOLD)",
        "zip.pearl.impactInstruction": "If an AI follows the instructions in the ZIP, it could disclose information it can access or take actions you did not intend.",
        "zip.pearl.impactSHA": "The SHA check confirms a match in the covered database. The file’s behavior and effects if opened are unverified.",
        "zip.pearl.impactTitle": "What could happen",
        "zip.pearl.incomplete": "Some checks could not be completed",
        "zip.scope.structureChecked": "Outer ZIP structure metadata checked",
        "zip.scope.structurePartial": "Outer ZIP structure has unresolved checks",
        "zip.scope.outerText": "Outer text · {p0} read · {p1} out of scope · {p2} unchecked",
        "zip.scope.outerCoverage": "Outer text · {p0} read · {p1} SHA only · {p2} contents unchecked",
        "zip.scope.innerText": "Inner archives · {p1} of {p0} have unchecked contents · {p2} text files read",
        "zip.scope.shaNotApplicable": "The outer ZIP has no files in scope for SHA lookup",
        "zip.scope.shaOuterOnly": "Known-hash checks cover direct members of the outer ZIP. Inner text is checked separately.",
        "zip.scope.noText": "No text files in scope for instruction scanning",
        "zip.scope.partial": "Part of the inspection is on hold",
        "zip.scope.checkFailed": "Some checks failed",
        "zip.scope.unavailable": "ZIP inspection failed",
        "zip.scope.scopeLimited": "Inspection coverage is limited",
        "zip.scope.formatExcluded": "Some formats are outside text inspection scope",
        "zip.scope.checkedText": "No rule matches in the text that was checked",
        "zip.scope.noCheckedText": "No text could be checked for instructions",
        "zip.scope.reason.unsafePath": "The archive path is unsafe or has no unambiguous destination",
        "zip.scope.unscannedItems": "Uninspected ZIP entries remain (total unknown)",
        "zip.scope.wholeOnHold": "Decision on the full ZIP is on hold",
        "zip.scope.innerDetail": "{p0} · {p1} text files read",
        "zip.scope.reason.count": "{p0} · {p1}",
        "zip.scope.reason.document": "Unsupported document format, such as PDF",
        "zip.scope.reason.executable": "Executable contents outside inspection scope",
        "zip.scope.reason.binary": "Unsupported binary format",
        "zip.scope.reason.encoding": "Document unreadable with supported encodings",
        "zip.scope.reason.characters": "Characters that may affect text visibility",
        "zip.scope.reason.innerFormat": "Unsupported inner archive format",
        "zip.scope.reason.innerHeader": "Could not verify the inner archive format",
        "zip.scope.reason.innerPartial": "Inner archive with an incomplete check",
        "zip.scope.reason.links": "Links or special files",
        "zip.scope.reason.depth": "Archives nested beyond one level",
        "zip.scope.reason.innerSize": "Inner archive text-inspection limit (4 MiB each)",
        "zip.scope.reason.readBudget": "Shared member read budget (64 MiB)",
        "zip.scope.reason.declaredSize": "Declared total uncompressed size exceeds 64 MiB",
        "zip.scope.reason.textBudget": "Text read limit (4 MiB per file, 32 MiB total)",
        "zip.scope.reason.lookup": "Known-hash database lookup failed",
        "zip.scope.reason.input": "The source ZIP was unreadable or could only be checked in part",
        "zip.scope.reason.time": "Inspection time limit",
        "zip.scope.reason.limit": "Size, count, or read budget limit",
        "zip.scope.reason.structure": "ZIP structure or integrity could not be verified",
        "zip.scope.nextInner": "Check the unchecked inner files in Details and inspect them individually.",
        "zip.scope.nextDocument": "Review the document named in Details locally, or provide its text separately.",
        "zip.scope.nextLimit": "Separate the unchecked items and inspect them in ZIPs within the limits.",
        "zip.scope.nextBounded": "Separate the items that reached inspection limits and check them again. See Details for the other unchecked items.",
        "zip.scope.nextLookup": "Check the lookup status in Details and retry once the inspection environment is available.",
        "zip.scope.nextFailed": "Check the reason in Details and verify the source ZIP before inspecting it again.",
        "zip.scope.nextOutDocument": "The completed results are available. Review the unchecked document locally or provide its text separately.",
        "zip.scope.nextOutFormats": "The completed results are available. Check the excluded formats individually with a method suited to them.",
        "zip.mint.instructionTitle": "Instruction document check",
        "zip.mint.noFindings": "No findings in the checked instruction document scope",
        "zip.mint.incomplete": "Some instruction document checks are incomplete",
        "zip.mint.coverage": "Instruction documents · {p0} checked · {p1} out of scope · {p2} unchecked",
        "zip.mint.checkedCount": "Instruction documents · {p0} checked",
        "zip.mint.reason.noBody": "Recognized non-text format, metadata, or empty file",
        "zip.mint.safetyLimit": "ZIP safety, excluded contents, and the safety of running files remain undetermined.",
        "zip.mint.nextUnread": "Check the affected items and reasons in Details, then retry with readable copies.",
        "zip.mint.unreadTitle": "Unchecked instruction document items and reasons",
        "zip.mint.excludedTitle": "Items outside instruction document scope",
        "zip.mint.shaUnreadTitle": "Items not checked against known SHA hashes",
        "zip.pearl.innerArchivePriority": "Inner archives with unchecked contents · {p0}",
        "zip.pearl.innerZipPriority": "Inner ZIP files with unchecked contents · {p0}",
        "zip.pearl.instructionTitle": "Suspicious instructions",
        "zip.pearl.matchingFiles": "Entries matching a known SHA",
        "zip.pearl.nextInnerArchive": "Select Review details for the file names. Hold off on sharing this ZIP with AI.",
        "zip.pearl.nextInstruction": "Review the flagged text in context, and hold off on sharing the ZIP with AI.",
        "zip.pearl.nextPause": "Review the evidence and unchecked items, and hold off on sharing the ZIP with AI.",
        "zip.pearl.nextScoped": "Review the inspection scope, then verify the sender and the purpose of the files.",
        "zip.pearl.nextSHA": "Review the details and hold off on opening or running matching files or sharing this ZIP with AI.",
        "zip.pearl.nextTitle": "What you can do now",
        "zip.pearl.noInstruction": "None detected by the rules used",
        "zip.pearl.open": "Show inspection results",
        "zip.pearl.outerTextRead": "Text files read directly from this ZIP · {p0}",
        "zip.pearl.pause": "Pause before sharing this ZIP with AI",
        "zip.pearl.priorityFiles": "Files to review first",
        "zip.pearl.review": "Review details",
        "zip.pearl.ruleAuthority": "Claimed authorization",
        "zip.pearl.ruleExecution": "Tool execution request",
        "zip.pearl.ruleLimit": "Existing rules are applied to selected text. Quoted text can also match a rule.",
        "zip.pearl.ruleOverride": "Override of earlier instructions",
        "zip.pearl.rulePrivilege": "Privilege request",
        "zip.pearl.ruleRole": "Role impersonation",
        "zip.pearl.ruleSuppression": "Suppression of findings",
        "zip.pearl.ruleTransmission": "Data transfer request",
        "zip.pearl.scoped": "No findings within the checked scope",
        "zip.pearl.scopeLimit": "The safety of the entire ZIP remains undetermined.",
        "zip.pearl.scopeTitle": "Inspection scope",
        "zip.pearl.shaCoverage": "ZIP SHA check: Checked {p0} · Unchecked {p1} · Matches {p2}",
        "zip.pearl.shaUnlisted": "Known SHA not checked because archive entries were not listed.",
        "zip.pearl.shaIncomplete": "Some items could not be checked for SHA matches",
        "zip.pearl.shaMatch": "A file in the ZIP matched a known hash in the covered database",
        "zip.pearl.shaNoMatch": "No match in the covered database",
        "zip.pearl.shaTitle": "Known SHA check",
        "zip.pearl.textScope": "SHA only: {p0} · Text outside scope or unchecked: {p1}",
        "zip.pearl.textCoverage": "Entries listed: {p0} · Text files read: {p1}",
        "zip.pearl.title": "ZIP inspection results",
        "zip.pearl.unchecked": "Some items remain unchecked.",
        "zip.pearl.unknownReasons": "Reasons checks could not be completed",
        "zip.pearl.untrusted": "Untrusted data from the ZIP",
        "zip.select": "Select ZIP to inspect",
        "zip.select_prompt": "Choose one ZIP file to inspect.",
        "zip.sha.db_update": "Database freshness is unverified; a nonmatch cannot be established.",
        "zip.sha.incomplete": "Some items could not be inspected.",
        "zip.sha.match": "Match found among the stored SHA values. This is not a final danger verdict.",
        "zip.sha.no_match": "No match in the covered database (not proof of safety).",
        "zip.title": "ZIP SHA-256 inspection",
        "zip.uninspectable": "Inspection unavailable — result not accepted.",
        "zip.warn_icon.a11y": "Warning: suspicious instructions",
    ]
    static let requiredEnglishKeys: Set<String> = ["review.diff_absence", "review.diff_deleted", "review.diff_incomplete", "review.diff_state", "review.empty_added", "review.registration_busy", "zip.home.title", "zip.home.scope", "meaning.limit.format", "meaning.limit.lines", "meaning.limit.many", "meaning.limit.multiline", "meaning.limit.none", "meaning.limit.pattern", "meaning.limit.unknown", "meaning.rule.follow", "meaning.rule.ignore", "meaning.rule.local_log", "meaning.rule.no_send", "meaning.rule.send_https", "meaning.rule.unknown", "meaning.scope", "meaning.summary.add", "meaning.summary.delete", "meaning.summary.follow_ignore", "meaning.summary.ignore_follow", "meaning.summary.replace", "meaning.summary.send", "meaning.unexplained", "monitor.description", "monitor.detected.alert", "monitor.detected.review", "monitor.detection_disclaimer", "monitor.kind.uninspectable", "monitor.pending.count", "monitor.pending.no_auto_accept", "monitor.pending.remain", "monitor.reason.generic", "monitor.recovery_suppressed", "monitor.register", "monitor.register_first", "monitor.review_pending", "monitor.root.check", "monitor.start", "monitor.start_failed", "monitor.start_save_failed", "monitor.starting", "monitor.state.pending", "monitor.state.stopped", "monitor.state.stopped_pending", "monitor.state.unknown", "monitor.state.unknown_pending", "monitor.state.verify_registration", "monitor.state.watching", "monitor.stop", "monitor.stop_requested", "monitor.stop_save_failed", "monitor.stop_unverified", "monitor.stopped_after", "monitor.unknown.no_running_claim", "monitor.unknown.not_unregistered", "monitor.unregistered.detail", "monitor.unregistered.no_baseline", "quit.confirm", "quit.consequences", "quit.stop_and_quit", "registration.adopt_confirm", "registration.adopt_explain", "registration.adopt_question", "registration.ask", "registration.changed", "registration.confirm", "registration.explain", "registration.generic_hold", "registration.invalid_pending", "registration.missing_baseline", "registration.no_files", "registration.old_active", "registration.pick", "registration.pointer_failed", "registration.preview_incomplete", "registration.preview_unavailable", "registration.reason.accept", "registration.reason.busy", "registration.reason.changed", "registration.reason.choice", "registration.reason.invalid", "registration.reason.io", "registration.reason.monitor", "registration.reason.path", "registration.reason.running", "registration.reason.state", "registration.runtime_invalid", "registration.unreadable", "residency.disabled_candidate", "residency.login_choice", "residency.login_disabled", "residency.monitor_choice", "residency.os_line", "residency.pause_reason", "residency.reason_line", "residency.registered_not_running", "review.accept", "review.accept_changed", "review.accept_failed", "review.accept_precheck_failed", "review.accepted", "review.compare", "review.diff_changed", "review.diff_colors", "review.diff_hash_mismatch", "review.diff_limit", "review.diff_old_missing", "review.diff_size", "review.diff_unavailable", "review.diff_unknown", "review.diff_unsafe", "review.diff_utf8", "review.explanation", "review.explanation_not_verdict", "review.meaning_inconsistent", "review.meaning_missing", "review.original_line", "review.pending_cancel", "review.rejected", "review.review_changed", "review.title", "review.unexplained_reasons", "review.view_original_diff_sha", "runtime.debug", "runtime.invalid", "runtime.line", "runtime.verified", "sha.coverage", "sha.db.clock", "sha.db.failed", "sha.db.ready", "sha.db.stale", "sha.db_composition", "sha.db_coverage_limit", "sha.db_unverified", "sha.match", "sha.mode.age_test", "sha.mode.failed_test", "sha.no_execute", "sha.no_match", "sha.self_check", "sha.self_check_not_detection", "sha.uninspectable", "sha.update_off", "ui.common.cancel", "ui.common.details", "ui.common.later", "ui.common.not_verified", "ui.header.build", "ui.language.save_unverified", "ui.translation.defect", "ui.value.stopped", "zip.abort", "zip.baseline.limits", "zip.baseline.monitor", "zip.baseline.scope", "zip.bounds", "zip.cancel", "zip.description", "zip.discarded", "zip.failure_reason", "zip.instruction.detected", "zip.instruction.incomplete", "zip.instruction.not_detected", "zip.instruction.not_started", "zip.quit_wait", "zip.report.simulation", "zip.sha.db_update", "zip.sha.incomplete", "zip.sha.match", "zip.sha.no_match", "zip.uninspectable", "zip.warn_icon.a11y"]
    static var englishReady: Bool {
        let additionalKeys: Set<String> = [
            "registration.switch.action", "registration.switch.ask", "registration.switch.done",
            "registration.switch.evidence", "registration.switch.pick", "registration.switch.review",
            "registration.switch.same", "registration.switch.stop_confirm", "registration.switch.stop_explain",
            "registration.switch.stop_failed", "registration.switch.stop_question", "registration.switch.stopping",
            "registration.switch.unverified",
            "zip.instruction.zero.unsupported", "zip.instruction.zero.encoding",
            "zip.instruction.zero.size", "zip.instruction.zero.unreadable",
            "zip.action.decision.zeroThorough", "zip.action.decision.zeroHold", "zip.failure.archiveTooLarge",
        ]
        return requiredEnglishKeys.union(additionalKeys).allSatisfy {
            !(english[$0] ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }
}

let registrationReasonKeys: [String: String] = [
    "ACCEPTANCE_INCOMPLETE": "registration.reason.accept",
    "IO_ERROR": "registration.reason.io",
    "MONITOR_INVALID": "registration.reason.monitor",
    "OLD_MONITOR_RUNNING": "registration.reason.running",
    "PATH_UNSAFE": "registration.reason.path",
    "REGISTRATION_DIRECTORY_PERMISSIONS": "registration.reason.directory_permissions",
    "PREVIEW_CONFIRMATION_REQUIRED": "registration.reason.choice",
    "REGISTRATION_CHANGED": "registration.reason.changed",
    "REGISTRATION_INVALID": "registration.reason.invalid",
    "STATE_BUSY": "registration.reason.busy",
    "STATE_INVALID": "registration.reason.state",
    "SWITCH_EVIDENCE_UNAVAILABLE": "registration.switch.evidence",
    "SWITCH_OUTCOME_UNVERIFIED": "registration.switch.unverified",
]
