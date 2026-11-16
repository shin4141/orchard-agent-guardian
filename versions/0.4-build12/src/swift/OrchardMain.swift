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
    let key: String
    let path: String
    let kind: String
    let detectedAt: Date?
    let detectedEpoch: Double
    let lastActivityEpoch: Double
    let after: String?
}

private enum DisplayState {
    case unregistered
    case running([ChangeRow])
    case stopped([ChangeRow])
    case unknown([ChangeRow], String)

    var title: String {
        switch self {
        case .unregistered: return "🍎⏸ 未登録"
        case .running(let rows): return rows.isEmpty ? "🍎 見守り" : "🍎🔴 要確認 \(rows.count)件"
        case .stopped(let rows): return rows.isEmpty ? "🍎⏸ 停止中" : "🍎⏸🔴\(rows.count) 停止中"
        case .unknown(let rows, let reason): return rows.isEmpty ? (reason.hasPrefix("[登録確認]") ? "🍎⚠️ 登録を確認" : "🍎⚠️ 状態不明") : "🍎⚠️🔴\(rows.count) 状態不明"
        }
    }

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

private func loadDisplayState(root: String, stateDir: String,
                              registrationError: String?, monitor: [String: Any]?) -> DisplayState {
    if let registrationError { return .unknown([], registrationError) }
    if root.isEmpty || stateDir.isEmpty { return .unregistered }
    let baselinePath = stateDir + "/baseline.json"
    if !FileManager.default.fileExists(atPath: baselinePath) { return .unknown([], "[登録確認] 信頼基準が見つかりません。元の保存先を確認してください。自動初期化は行いません。") }
    do {
        let baseline = try readObject(baselinePath)
        guard let baselineRoot = baseline["root"] as? String,
              canonicalPath(baselineRoot) == root else {
            return .unknown([], "監視ルートが基準と一致しません")
        }
        let pending = try readObject(stateDir + "/pending.json")
        guard let changes = pending["changes"] as? [String: Any],
              let times = (pending["detected_at_epoch"] ?? [:]) as? [String: Any] else {
            return .unknown([], "pending の形式が不正です")
        }
        if changes.count > 1025 { return .unknown([], "pending 件数が上限を超えました") }

        var rows: [ChangeRow] = []
        let firstSeen = (pending["first_seen_epoch"] as? NSNumber)?.doubleValue ?? 0
        let lastSeen = (pending["last_seen_epoch"] as? NSNumber)?.doubleValue ?? firstSeen
        for path in changes.keys.sorted() {
            guard let change = changes[path] as? [String: Any],
                  let kind = change["kind"] as? String else {
                return .unknown([], "変更記録の形式が不正です")
            }
            let epoch = (times[path] as? NSNumber)?.doubleValue ?? firstSeen
            let safeEpoch = epoch.isFinite && epoch >= 0 ? epoch : 0
            let safeLastSeen = lastSeen.isFinite && lastSeen >= safeEpoch ? lastSeen : safeEpoch
            rows.append(ChangeRow(
                key: path, path: safeLabel(path), kind: safeLabel(kind),
                detectedAt: safeEpoch > 0 ? Date(timeIntervalSince1970: safeEpoch) : nil,
                detectedEpoch: safeEpoch, lastActivityEpoch: safeLastSeen,
                after: change["after"] as? String
            ))
        }
        switch monitor?["state"] as? String {
        case "RUNNING": return .running(rows)
        case "STOPPED": return .stopped(rows)
        case "UNKNOWN": return .unknown(rows, "監視プロセスの実稼働を確認できません")
        default: return .unknown(rows, "監視プロセスの状態を読み取れません")
        }
    } catch {
        return .unknown([], "保存状態を読み取れません")
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
        return ["\(phase)・未確認の変更: \(rows.count)件"] + rows.map {
            "\($0.path) · \($0.kind) · \(timestamp($0.detectedAt))"
        } + [rows.isEmpty ? "未確認の変更はありません" : "未確認の変更は残っています",
             "自動承認・復元は行いません"]
    case .unknown(let rows, let reason):
        return [rows.isEmpty ? "登録・未確認件数を確認できません（未登録とは判定しません）" : "状態不明・未確認の変更: \(rows.count)件"] + rows.map {
            "\($0.path) · \($0.kind) · \(timestamp($0.detectedAt))"
        } + [reason, "監視中とは表示しません"]
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

private func saveRegistration(root: String, stateDir: String, at path: String) throws {
    let result = registrationContinuity("save", path: path, root: root, stateDir: stateDir)
    guard result.status == "READY", result.root == root, result.stateDir == stateDir else {
        throw NSError(domain: "OrchardRegistrationContinuity", code: 1)
    }
}

@MainActor
private final class MenuController: NSObject, NSApplicationDelegate, NSMenuDelegate, NSWindowDelegate {
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
    private var item: NSStatusItem?
    private var timer: Timer?
    private let zipController = OrchardZipController()
    private var preview: NSWindow?
    private var previewTitle: NSTextField?
    private var previewDetails: NSTextField?
    private var previewMenuEvidence: NSTextField?
    private var previewActionResult: NSTextField?
    private var previewMonitorButton: NSButton?
    private var pendingRows: [ChangeRow] = []
    private var displayedTitle: String?
    private var displayedLines: [String] = []
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
        menu.addItem(withTitle: "Orchardを開く", action: #selector(reopenOrchard), keyEquivalent: "0").target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "Orchardを終了", action: #selector(quitApp), keyEquivalent: "q").target = self
        appItem.submenu = menu
        bar.addItem(appItem)
        let editItem = NSMenuItem()
        let edit = NSMenu(title: "編集")
        edit.addItem(withTitle: "コピー", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "すべて選択", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
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
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1100, height: 780),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Orchard 🍎"
        window.minSize = NSSize(width: 980, height: 700)
        window.isReleasedWhenClosed = false
        window.center()
        let heading = NSTextField(labelWithString: "Orchard 🍎")
        heading.font = .systemFont(ofSize: 30, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString: "ZIPを確かめる。指示ファイルの変更に気づく。")
        subtitle.textColor = .secondaryLabelColor
        let tag = NSTextField(wrappingLabelWithString: "Orchard 0.4  ·  build12  ·  実SHA 300,000件  ·  自動更新なし  ·  ログイン時の常駐登録は無効")
        tag.font = .systemFont(ofSize: 12)
        tag.textColor = .secondaryLabelColor
        let rightHeading = NSTextField(labelWithString: "指示ファイルの監視")
        rightHeading.font = .systemFont(ofSize: 20, weight: .semibold)
        let description = NSTextField(wrappingLabelWithString: "選んだフォルダ内のAGENTS.mdなど5種類を監視します。変更時は日本語説明と差分を確認してから承認できます。")
        let title = NSTextField(labelWithString: "")
        title.font = .systemFont(ofSize: 19, weight: .medium)
        let details = NSTextField(wrappingLabelWithString: "")
        details.font = .systemFont(ofSize: 12)
        details.isSelectable = true
        details.maximumNumberOfLines = 0
        let monitorButton = NSButton(title: "プロジェクトを登録", target: self, action: #selector(primaryMonitorAction))
        monitorButton.bezelStyle = .rounded
        monitorButton.setAccessibilityIdentifier("orchard.monitor.primary")
        let review = NSButton(title: "未確認の変更を確認", target: self, action: #selector(reviewFirstPending))
        review.bezelStyle = .rounded
        review.setAccessibilityIdentifier("orchard.monitor.review")
        let actionResult = NSTextField(wrappingLabelWithString: "フォルダ登録後、明示的に監視を開始してください。")
        actionResult.font = .systemFont(ofSize: 12)
        actionResult.maximumNumberOfLines = 0
        let note = NSTextField(wrappingLabelWithString: "変更検知は攻撃・危険性の判定ではありません。未確認の証拠は、停止やアプリ再起動で消えません。")
        note.textColor = .secondaryLabelColor
        note.font = .systemFont(ofSize: 12)
        let right = NSStackView(views: [rightHeading, description, title, monitorButton, review, actionResult, details, note])
        right.orientation = .vertical
        right.alignment = .leading
        right.spacing = 14
        let divider = NSBox()
        divider.boxType = .separator
        let body = NSStackView(views: [zipController.view, divider, right])
        body.orientation = .horizontal
        body.alignment = .top
        body.spacing = 24
        let stack = NSStackView(views: [heading, subtitle, tag, body])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        let content = window.contentView!
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 28),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -28),
            stack.topAnchor.constraint(equalTo: content.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor, constant: -24),
            body.widthAnchor.constraint(equalTo: stack.widthAnchor),
            body.heightAnchor.constraint(greaterThanOrEqualToConstant: 500),
            zipController.view.widthAnchor.constraint(equalTo: body.widthAnchor, multiplier: 0.53),
            divider.widthAnchor.constraint(equalToConstant: 1),
            divider.heightAnchor.constraint(equalTo: body.heightAnchor),
            right.widthAnchor.constraint(equalTo: body.widthAnchor, multiplier: 0.47, constant: -49)
        ])
        previewTitle = title
        previewDetails = details
        previewActionResult = actionResult
        previewMonitorButton = monitorButton
        previewReviewButton = review
        previewActionResult?.stringValue = registrationIntake?.notice ?? ""
        preview = window
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func refresh() {
        let registered = !selectedRoot.isEmpty && !selectedStateDir.isEmpty &&
            FileManager.default.fileExists(atPath: selectedStateDir + "/baseline.json")
        monitorResponse = registered ? nativeMonitorStatus(root: selectedRoot,
                                                           stateDir: selectedStateDir) : nil
        var state = loadDisplayState(root: selectedRoot, stateDir: selectedStateDir,
                                     registrationError: registrationError,
                                     monitor: monitorResponse)
        if startingWatcher, case .stopped(let rows) = state,
           let ownedWatcher, ownedWatcher.isRunning {
            state = .unknown(rows, "監視プロセスの起動を確認中")
        }
        if state.isRunning && startingWatcher { previewActionResult?.stringValue = "監視中です。指示ファイルの変更を検知したら通知します。" }
        if state.isRunning || ownedWatcher?.isRunning == false { startingWatcher = false }
        if state.isRunning, let pid = monitorResponse?["pid"] as? Int,
           ownedWatcher?.isRunning != true || Int(ownedWatcher?.processIdentifier ?? -1) != pid {
            state = .unknown(state.rows, "[登録確認] 旧版または別のOrchardが監視中です。そちらで停止して終了後、登録を再確認してください。二重監視は開始しません。")
        }
        previewReviewButton?.isEnabled = state.permitsReview && !state.rows.isEmpty
        displayedState = state
        pendingRows = state.rows
        if let active = alertRow, !pendingRows.contains(where: { $0.key == active.key }) {
            alertPanel?.close()
        }
        if !state.isRunning { alertPanel?.close() }
        if state.isRunning && alertPanel == nil { showOneStableAlertIfNeeded() }
        let osRegistration = loginService.status
        let policy = sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)
        reconcileResidency(state: state, registration: osRegistration, policy: policy)
        let residencyLines = [
            "実行環境: \(options.runtimeError ?? (options.runtimeManifestSHA256 == nil ? "手動debug指定（同梱identity未検証）" : "起動時の同梱runtime同一性を確認済み（発行者の信頼証明は別）"))",
            "ログイン項目（macOS）: \(osRegistration.japanese)",
            "常駐の選択（保存希望）: \(policy.map { $0.desiredLogin ? "オン" : "オフ" } ?? "未確認")",
            "自動監視の希望: \(policy.map { $0.desiredMonitor ? "オン" : "停止" } ?? "未確認")",
            "自動監視の理由: \(policy?.japaneseReason ?? "保存状態を確認できません")",
            "ログイン時の自動起動: この版では無効",
        ]
        let currentLines = lines(for: state) + residencyLines
        switch state {
        case .unregistered:
            previewMonitorButton?.title = "プロジェクトを登録"
            previewMonitorButton?.isEnabled = true
        case .running:
            previewMonitorButton?.title = "監視を停止"
            previewMonitorButton?.isEnabled = true
        case .stopped:
            previewMonitorButton?.title = "監視を開始"
            previewMonitorButton?.isEnabled = true
        case .unknown:
            previewMonitorButton?.title = registrationIntake?.status == "CHOICE" ? "別の登録を確認" : "登録を再確認"
            previewMonitorButton?.isEnabled = true
        }
        guard state.title != displayedTitle || currentLines != displayedLines else { return }
        displayedTitle = state.title
        displayedLines = currentLines
        item?.button?.title = state.title
        item?.button?.toolTip = "Orchard — \(currentLines.first ?? "")"
        previewTitle?.stringValue = state.title
        let folder = selectedRoot.isEmpty ? (registrationError == nil ? "監視フォルダ: 未登録" : "監視フォルダ: 登録情報の確認待ち") : "監視フォルダ: " + safeLabel(selectedRoot)
        previewDetails?.stringValue = ([folder] + lines(for: state) + ["ログイン時の常駐: この版では無効"]).joined(separator: "\n")

        let menu = NSMenu(title: "Orchard")
        menu.delegate = self
        for (index, line) in currentLines.enumerated() {
            let entry = NSMenuItem(title: line, action: nil, keyEquivalent: "")
            if state.permitsReview && index > 0 && index <= pendingRows.count {
                entry.action = #selector(reviewItem(_:))
                entry.target = self
                entry.representedObject = pendingRows[index - 1].key
            } else {
                entry.isEnabled = false
            }
            menu.addItem(entry)
        }
        menu.addItem(.separator())
        let control: NSMenuItem
        switch state {
        case .unregistered:
            control = NSMenuItem(title: "プロジェクトを登録", action: #selector(registerProject), keyEquivalent: "")
        case .running:
            control = NSMenuItem(title: "監視を停止", action: #selector(stopMonitor), keyEquivalent: "")
        case .stopped:
            control = NSMenuItem(title: "監視を開始", action: #selector(startMonitor), keyEquivalent: "")
        case .unknown:
            control = NSMenuItem(title: "登録を再確認", action: #selector(refreshFromMenu), keyEquivalent: "")
        }
        control.target = self
        menu.addItem(control)
        menu.addItem(.separator())
        let enableLogin = NSMenuItem(title: "ログイン時の監視を有効にする…", action: #selector(enableResidency), keyEquivalent: "")
        enableLogin.target = self
        enableLogin.isEnabled = false // No registration in this private integration build.
        menu.addItem(enableLogin)
        let disableLogin = NSMenuItem(title: "ログイン登録を解除し、監視を停止する…", action: #selector(disableResidency), keyEquivalent: "")
        disableLogin.target = self
        disableLogin.isEnabled = false
        menu.addItem(disableLogin)
        menu.addItem(.separator())
        let reopen = NSMenuItem(title: "Orchardを開く", action: #selector(reopenOrchard), keyEquivalent: "")
        reopen.target = self
        menu.addItem(reopen)
        let quit = NSMenuItem(title: "Orchardを終了", action: #selector(quitApp), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        item?.menu = menu
    }

    private func showOneStableAlertIfNeeded() {
        let now = Date().timeIntervalSince1970
        for row in pendingRows where now - row.lastActivityEpoch >= options.panelDebounce {
            let identity = "\(row.key)|\(row.detectedEpoch)|\(row.after ?? "NONE")"
            if completedAlertClaims.contains(identity) { continue }
            if let last = lastAlertClaimAttempt[identity], now - last < 5 { continue }
            lastAlertClaimAttempt[identity] = now
            let (status, response, _) = callDetector("claim-alert", arguments: [
                "--path", row.key, "--reviewed-after", row.after ?? "NONE",
                "--detected-at", String(row.detectedEpoch)
            ])
            guard status == 0 else { continue }
            completedAlertClaims.insert(identity)
            guard (response?["claimed"] as? Bool) == true else { continue }
            showAlertPanel(for: row)
            return
        }
    }

    private func showAlertPanel(for row: ChangeRow) {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 210),
            styleMask: [.titled, .closable], backing: .buffered, defer: false
        )
        panel.title = "Orchard Sentinel — 変更を検知"
        panel.isFloatingPanel = true
        panel.hidesOnDeactivate = false
        panel.level = .floating
        panel.delegate = self
        panel.center()
        let heading = NSTextField(labelWithString: "指示ファイルの変更を検知しました")
        heading.font = .boldSystemFont(ofSize: 16)
        let detail = NSTextField(wrappingLabelWithString:
            "ファイル: \(row.path)\n検出: \(timestamp(row.detectedAt))\n種類: \(kindLabel(row.kind))")
        detail.font = .systemFont(ofSize: 13)
        let review = NSButton(title: "変更内容を確認", target: self, action: #selector(reviewFromPanel))
        let later = NSButton(title: "あとで", target: self, action: #selector(deferPanel))
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
        alertPanel = panel
        alertRow = row
        panel.orderFrontRegardless() // intentionally non-modal
    }

    private func kindLabel(_ kind: String) -> String {
        switch kind {
        case "ADDED": return "追加"
        case "DELETED": return "削除"
        case "CHANGED": return "変更"
        case "UNINSPECTABLE": return "比較できない状態"
        default: return "状態変更"
        }
    }

    @objc private func deferPanel() {
        alertPanel?.close() // claim remains; pending and 🍎🔴 remain
    }

    @objc private func reviewFromPanel() {
        guard let row = alertRow else { return }
        alertPanel?.close()
        guard let entry = item?.menu?.items.first(where: { $0.representedObject as? String == row.key }),
              let action = entry.action else { return }
        NSApp.sendAction(action, to: entry.target, from: entry)
    }

    func windowWillClose(_ notification: Notification) {
        guard let window = notification.object as? NSWindow, window === alertPanel else { return }
        alertPanel = nil
        alertRow = nil
    }

    @objc private func quitApp() {
        if SentinelResidencyBuild.activationAllowed,
           sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)?.desiredLogin == true {
            let alert = NSAlert()
            alert.messageText = "監視を停止してアプリを終了しますか"
            alert.informativeText = "終了後と次回ログイン後も、自動監視は停止します。手動で監視再開を選ぶまで勝手に開き直しません。ログイン登録は残り、未確認変更・原文・履歴は保持します。登録解除は別の操作です。"
            alert.addButton(withTitle: "監視を停止して終了")
            alert.addButton(withTitle: "キャンセル")
            alert.buttons[0].keyEquivalent = ""
            alert.buttons[1].keyEquivalent = "\r"
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            guard residencyCommand("quit") != nil else {
                showResult("終了の選択を保存できません。自動復旧を抑止できないため終了しません。")
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
        guard let entry = item?.menu?.items.first(where: { $0.action == #selector(reviewItem(_:)) }),
              let action = entry.action else { return }
        NSApp.sendAction(action, to: entry.target, from: entry)
    }

    @objc private func primaryMonitorAction() {
        switch displayedState {
        case .unregistered: registerProject()
        case .running: stopMonitor()
        case .stopped: startMonitor()
        case .unknown: reloadRegistration()
        }
    }

    @objc private func refreshFromMenu() { reloadRegistration() }

    private func reloadRegistration() {
        if let choice = registrationIntake, choice.status == "CHOICE" {
            let alert = NSAlert()
            alert.messageText = "見つかった登録を引き継ぎますか"
            alert.informativeText = "公開版とは別の保存先です。\nプロジェクト: " + safeLabel(choice.root) +
                "\n未確認変更: \(choice.pendingCount)件。元の保存先を参照し、承認・移動・削除は行いません。監視は手動開始です。"
            alert.addButton(withTitle: "確認して引き継ぐ"); alert.addButton(withTitle: "キャンセル")
            alert.buttons[0].keyEquivalent = ""; alert.buttons[1].keyEquivalent = "\r"
            guard alert.runModal() == .alertFirstButtonReturn else { return }
            applyRegistration(registrationContinuity("adopt-preview", path: options.registrationPath, expected: choice.token))
        } else {
            applyRegistration(registrationContinuity("resolve", path: options.registrationPath,
                ownedPID: ownedWatcher?.isRunning == true ? ownedWatcher?.processIdentifier : nil))
        }
        refresh()
    }

    private func applyRegistration(_ result: RegistrationIntake) {
        registrationIntake = result
        if result.status == "READY" {
            selectedRoot = result.root; selectedStateDir = result.stateDir; registrationError = nil
            previewActionResult?.stringValue = result.notice
        } else if result.status == "UNREGISTERED" {
            selectedRoot = ""; selectedStateDir = ""; registrationError = nil
        } else { registrationError = "[登録確認] " + result.message }
    }

    private func registrationReadyForAction() -> Bool {
        let result = registrationContinuity("check", path: options.registrationPath, root: selectedRoot,
            stateDir: selectedStateDir, ownedPID: ownedWatcher?.isRunning == true ? ownedWatcher?.processIdentifier : nil)
        if result.status != "READY" { applyRegistration(result); refresh(); return false }
        return true
    }

    @objc private func registerProject() {
        if registrationError != nil { reloadRegistration(); return }
        if selectedRoot.isEmpty {
            let picker = NSOpenPanel()
            picker.message = "監視するプロジェクトを明示的に選択してください"
            picker.canChooseDirectories = true
            picker.canChooseFiles = false
            picker.allowsMultipleSelection = false
            picker.begin { [weak self] result in
                guard result == .OK, let url = picker.url else { return }
                self?.presentRegistration(for: canonicalPath(url.path))
            }
        } else {
            presentRegistration(for: selectedRoot)
        }
    }

    private func presentRegistration(for root: String) {
        let stateDir = selectedStateDir.isEmpty
            ? URL(fileURLWithPath: options.registrationPath).deletingLastPathComponent()
                .appendingPathComponent("state-" + UUID().uuidString).path
            : selectedStateDir
        let (previewCode, preview, _) = callDetector("registration-preview",
                                                     root: root, stateDir: stateDir)
        guard previewCode == 0, let preview,
              let token = preview["snapshot_token"] as? String, token.count == 64,
              let entries = preview["files"] as? [[String: Any]],
              let previewRoot = preview["root"] as? String,
              canonicalPath(previewRoot) == root else {
            showResult("現在の指示ファイルを安全に一覧表示できません。登録しません。")
            return
        }
        var details = ["プロジェクト: \(root)", "監視対象: \(entries.count)件"]
        for entry in entries {
            guard let path = entry["path"] as? String,
                  let digest = entry["sha256"] as? String,
                  let content = entry["content"] as? String else {
                showResult("登録プレビューの内容が不完全です。登録しません。")
                return
            }
            details.append("\nファイル: \(path)\nSHA-256: \(digest)\n--- 原文 ---\n\(content)\n--- ここまで ---")
        }
        if entries.isEmpty { details.append("監視対象の指示ファイルは現在ありません。今後の追加を監視します。") }
        let alert = NSAlert()
        alert.messageText = "このプロジェクトを登録しますか"
        alert.informativeText = "表示された現在の内容を確認してから登録してください。登録時の内容を信頼基準にします。監視は登録後も停止中です。"
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 700, height: 350))
        text.isEditable = false
        text.isSelectable = true
        text.isAutomaticLinkDetectionEnabled = false
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        text.string = details.joined(separator: "\n")
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 720, height: 350))
        scroll.hasVerticalScroller = true
        scroll.documentView = text
        alert.accessoryView = scroll
        alert.addButton(withTitle: "この内容を確認して登録")
        alert.addButton(withTitle: "キャンセル")
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        let chosenRoot = root
        DispatchQueue.main.async { [weak self] in
            guard let self, alert.runModal() == .alertFirstButtonReturn else { return }
            self.finishRegistration(root: chosenRoot, stateDir: stateDir, token: token)
        }
    }

    private func finishRegistration(root: String, stateDir: String, token: String) {
        let (initCode, _, _) = callDetector("init", arguments: [
            "--confirm", "--expected-snapshot", token,
        ], root: root, stateDir: stateDir)
        guard initCode == 0 else {
            showResult("登録前の内容が変わったか、信頼基準を作れませんでした。再度内容を確認してください。")
            return
        }
        do {
            try saveRegistration(root: root, stateDir: stateDir, at: options.registrationPath)
            selectedRoot = root
            selectedStateDir = stateDir
            registrationError = nil
            previewActionResult?.stringValue = "登録しました。監視は停止中です。"
            refresh()
        } catch {
            selectedRoot = root
            selectedStateDir = stateDir
            showResult("信頼基準は作成しましたが、次回起動用の登録情報を保存できませんでした。")
            refresh()
        }
    }

    @objc private func startMonitor() {
        guard registrationReadyForAction() else { return }
        if SentinelResidencyBuild.activationAllowed,
           sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)?.desiredLogin == true {
            guard residencyCommand("resume", arguments: ["--human-confirmed"]) != nil else {
                showResult("監視再開の明示選択を保存できません。監視は開始しません。")
                return
            }
            launchHelperForExplicitChoice()
        }
        recoverySuppressed = false
        launchWatcher(automatic: false)
    }

    private func launchWatcher(automatic: Bool) {
        guard case .stopped = displayedState,
              options.runtimeError == nil, let python = options.pythonPath, let detector = options.detectorPath,
              Bundle.main.bundleURL.pathExtension != "app" || SentinelRuntime.validates(python: python, script: detector) else { return }
        let process = Process()
        let token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        process.executableURL = URL(fileURLWithPath: python)
        process.arguments = ["-I", "-S", "-B", detector, "watch", "--root", selectedRoot,
                             "--state-dir", selectedStateDir, "--quiet",
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
            previewActionResult?.stringValue = "監視プロセスの起動を確認中"
            if !automatic { refresh() }
        } catch {
            if automatic {
                previewActionResult?.stringValue = "自動復旧を試せませんでした。有限回数で打ち切ります。未確認証拠は保持しています。"
            } else {
                showResult("監視プロセスを起動できませんでした。未確認証拠は保持しています。")
            }
        }
    }

    @objc private func stopMonitor() {
        recoverySuppressed = true
        if SentinelResidencyBuild.activationAllowed,
           sentinelPolicy(root: selectedRoot, stateDir: selectedStateDir)?.desiredLogin == true {
            guard residencyCommand("pause") != nil else {
                showResult("停止の選択を保存できません。実際の停止状態を確認してください。")
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
            previewActionResult?.stringValue = "監視停止を要求しました。未確認証拠は保持します。"
            refresh()
        } else {
            showResult("監視停止を確認できませんでした。状態を再確認してください。")
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
        guard SentinelResidencyBuild.activationAllowed, !residencyMutationInFlight else { return }
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
            previewActionResult?.stringValue = "復旧判断を確認できません。自動復旧を止め、未確認変更を保持しています。"
            return
        }
        if outcome["action"] as? String == "START" {
            launchWatcher(automatic: true)
        } else if outcome["action"] as? String == "WAIT",
                  let due = outcome["retry_at_epoch"] as? Double {
            nextRecoveryProbe = Date(timeIntervalSince1970: due)
        } else if outcome["action"] as? String == "PAUSED" {
            previewActionResult?.stringValue = "自動復旧を停止しました。手動で監視再開を選んでください。未確認変更は保持しています。"
        }
    }

    @objc private func enableResidency() {
        guard SentinelResidencyBuild.activationAllowed else {
            showResult("常駐の実装候補です。実機登録は別Gateのため無効です。ログイン項目や監視希望は変更していません。")
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
            showResult("常駐用の登録情報とアプリidentityを確認できません。登録しません。")
            return
        }
        let alert = NSAlert()
        alert.messageText = "ログイン時の監視を有効にしますか"
        alert.informativeText = "選択済みプロジェクトを次回ログイン時にも監視します。クラッシュ時は有限回数で復旧します。変更の承認・ファイル実行・外部送信は行いません。監視停止や終了後も未確認変更は保持し、ログイン登録の解除は別に表示します。macOSの承認が必要な場合があります。"
        alert.addButton(withTitle: "この説明を確認して有効にする")
        alert.addButton(withTitle: "キャンセル")
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard residencyCommand("enable", arguments: ["--human-confirmed"]) != nil else {
            showResult("明示選択か信頼基準を確認できません。登録しません。")
            return
        }
        recoverySuppressed = false
        do {
            try loginService.register()
            launchHelperForExplicitChoice()
            showResult("macOSのログイン項目: \(loginService.status.japanese)。登録状態だけで監視中とは判断しません。")
        } catch {
            showResult("ログイン登録を完了できません。macOSの状態: \(loginService.status.japanese)。保存希望と登録状態は別です。")
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
            showResult("候補buildではOS登録の変更は無効です。現在の監視停止は「監視を停止」から選べます。")
            return
        }
        guard !residencyMutationInFlight else { return }
        let alert = NSAlert()
        alert.messageText = "ログイン登録を解除し、監視を停止しますか"
        alert.informativeText = "次回ログインの自動監視と自動復旧を止めます。未確認変更・原文・承認履歴は削除しません。解除に失敗した場合はmacOSの実際の登録状態を表示します。"
        alert.addButton(withTitle: "登録を解除して監視を停止")
        alert.addButton(withTitle: "キャンセル")
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
            self.showResult("macOSのログイン項目: \(self.loginService.status.japanese)。\(succeeded && saved ? "解除の応答と停止希望の保存を確認しました。" : "解除または保存を完了できていません。")監視の停止完了はleaseとscanで別に確認します。未確認変更は保持しています。")
            self.refresh()
        }
    }

    private func callDetector(_ command: String, arguments: [String] = [],
                              root: String? = nil, stateDir: String? = nil) -> (Int32, [String: Any]?, String) {
        if !["registration-preview", "init"].contains(command), !registrationReadyForAction() {
            return (78, nil, "登録・保存状態を確認できません。記録は保持しています。")
        }
        return runDetector(options: options, root: root ?? selectedRoot,
                           stateDir: stateDir ?? selectedStateDir,
                           command: command, arguments: arguments)
    }

    private func showResult(_ message: String) {
        previewActionResult?.stringValue = message
        let alert = NSAlert()
        alert.messageText = "Orchard"
        alert.informativeText = message
        alert.addButton(withTitle: "閉じる")
        alert.runModal()
    }

    private func reviewReason(_ raw: String) -> String {
        switch raw {
        case "Trusted old content was not saved; a safe diff is unavailable":
            return "信頼済みの旧内容が保存されていないため、差分を作れません。"
        case "Saved old content disagrees with the trusted hash":
            return "保存された旧内容と信頼基準のハッシュが一致しません。"
        case "Target exceeds the 64 KiB comparison cap":
            return "対象が比較上限の64 KiBを超えています。"
        case "Target is not valid UTF-8":
            return "対象をUTF-8のテキストとして安全に表示できません。"
        case "Target is not a regular file", "Target is unreadable or unsafe":
            return "対象が通常ファイルではないか、読み取れません。"
        case "Current target no longer matches pending evidence", "Current content changed during review":
            return "対象が検知時から変わりました。再検出後に確認してください。"
        case "Diff cannot be compared safely within the PoC limit":
            return "差分が表示上限を超えています。"
        default:
            return "保存状態または対象を安全に比較できません。再検出後に確認してください。"
        }
    }

    private func acceptReason(_ raw: String) -> String {
        switch raw {
        case "REFUSED_CHANGED_AFTER_REVIEW":
            return "確認後に内容または検出状態が変わりました。改めて確認してください。"
        case "REFUSED_CHANGED_DURING_ACCEPT":
            return "承認処理中に内容が変わりました。未確認状態は保持しています。"
        case "REFUSED_CHANGED_OR_UNSAFE":
            return "承認直前に対象を安全に再検査できませんでした。未確認状態は保持しています。"
        default:
            return "承認できませんでした。未確認状態と履歴を確認してください。"
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

    private func meaningLines(_ raw: Any?, heading: String) -> String? {
        guard let records = raw as? [[String: Any]] else { return nil }
        if records.isEmpty { return heading + "\n（この側に変更行はありません）" }
        var lines = [heading]
        for record in records {
            guard let number = record["line"] as? Int, number > 0,
                  let original = record["original"] as? String,
                  let meaning = record["meaning_ja"] as? String, !meaning.isEmpty else {
                return nil
            }
            lines.append("行\(number)  原文: \(evidenceText(original))")
            lines.append("           説明: \(meaning)")
        }
        return lines.joined(separator: "\n")
    }

    private func showMeaningFirst(_ raw: Any?, path: String) -> Bool {
        guard let meaning = raw as? [String: Any],
              let version = meaning["version"] as? Int, version == 1,
              let status = meaning["status"] as? String,
              status == "EXPLAINED" || status == "UNEXPLAINED",
              let summary = meaning["summary_ja"] as? String, !summary.isEmpty,
              let scope = meaning["scope_ja"] as? String,
              let beforeRecords = meaning["before_lines"] as? [[String: Any]],
              let afterRecords = meaning["after_lines"] as? [[String: Any]],
              let before = meaningLines(meaning["before_lines"], heading: "変更前の指示（変更行）"),
              let after = meaningLines(meaning["after_lines"], heading: "変更後の指示（変更行）"),
              let limitations = meaning["limitations_ja"] as? [String] else {
            showResult("日本語説明のデータが不足しています。承認はできません。")
            return false
        }
        if (status == "EXPLAINED" && (!limitations.isEmpty ||
            beforeRecords.count + afterRecords.count == 0 ||
            (beforeRecords + afterRecords).contains(where: { $0["rule_id"] as? String == nil }))) ||
            (status == "UNEXPLAINED" && (limitations.isEmpty ||
            summary != "変更は検知しましたが、意味を正確に説明できません")) {
            showResult("日本語説明と根拠行が一致しません。承認はできません。")
            return false
        }
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "\(safeLabel(path)) の指示変更を日本語で確認"
        alert.informativeText = summary + "\n" + scope
        var parts = [before, after]
        if !limitations.isEmpty {
            parts.append("説明できない理由\n" + limitations.map { "・" + $0 }.joined(separator: "\n"))
        }
        parts.append("これは変更内容の説明です。安全性や攻撃の判定ではありません。")
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 720, height: 400))
        text.isEditable = false
        text.isSelectable = true
        text.isAutomaticLinkDetectionEnabled = false
        text.font = .systemFont(ofSize: 14)
        text.string = parts.joined(separator: "\n\n")
        text.textContainer?.widthTracksTextView = true
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 740, height: 400))
        scroll.hasVerticalScroller = true
        scroll.documentView = text
        alert.accessoryView = scroll
        alert.addButton(withTitle: "原文・差分・SHA-256を確認")
        alert.addButton(withTitle: "あとで")
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        return alert.runModal() == .alertFirstButtonReturn
    }

    @objc private func reviewItem(_ item: NSMenuItem) {
        guard let key = item.representedObject as? String else { return }
        let (status, object, raw) = callDetector("review", arguments: ["--path", key])
        guard status == 0, let review = object,
              let token = review["review_token"] as? String,
              let after = review["after"] as? String,
              let diff = review["diff"] as? String else {
            let reason = reviewReason((object?["reason"] as? String) ?? String(raw.prefix(300)))
            showResult("安全に差分を比較できません。承認はできません。\n理由: " + reason)
            refresh()
            return
        }
        let before = review["before"] as? String
        let safePath = safeLabel(key)
        guard showMeaningFirst(review["meaning_ja"], path: key) else { return }
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "\(safePath) の変更内容を比較"
        alert.informativeText = "基準 SHA-256: \(before ?? "なし（追加）")\n現在 SHA-256: \(after)\n赤は旧内容、緑は現在の内容です。変更検知は危険性の判定ではありません。"
        let text = NSTextView(frame: NSRect(x: 0, y: 0, width: 720, height: 400))
        text.isEditable = false
        text.isSelectable = true
        text.isAutomaticLinkDetectionEnabled = false
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
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
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 740, height: 400))
        scroll.hasVerticalScroller = true
        scroll.documentView = text
        alert.accessoryView = scroll
        alert.addButton(withTitle: "この変更を確認して承認")
        alert.addButton(withTitle: "キャンセル")
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        let (acceptStatus, outcome, response) = callDetector("accept", arguments: [
            "--path", key, "--review-token", token,
            "--reviewed-before", before ?? "NONE", "--reviewed-after", after,
            "--human-confirmed"
        ])
        refresh()
        if acceptStatus == 0 && (outcome?["result"] as? String) == "ACCEPTED" {
            showResult("承認しました: \(safePath)\n新しい基準: \(after)")
        } else {
            let reason = (outcome?["result"] as? String) ?? String(response.prefix(300))
            showResult("承認を拒否しました: \(safePath)\n\(acceptReason(reason))\n結果コード: \(safeLabel(reason))")
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        guard menu === item?.menu else { return }
        let titles = menu.items.filter { !$0.isSeparatorItem }.map(\.title)
        previewMenuEvidence?.stringValue = "実メニューが開きました:\n" + titles.joined(separator: "\n")
    }
}

@main private enum SentinelMenuEntry {
    static func main() throws {
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
                                         registrationError: options.registrationError, monitor: monitor)
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
                fputs("同梱runtimeの同一性を確認できません。起動を停止しました。\n", stderr)
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
