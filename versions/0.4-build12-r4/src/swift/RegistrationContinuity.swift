import Foundation
import Darwin

// Process completion is delivered through Foundation's run loop, including
// before NSApplication.run(). Keep servicing it within the existing deadline.
private func registrationExit(_ process: Process, within seconds: TimeInterval) -> Bool {
    let deadline = ProcessInfo.processInfo.systemUptime + seconds
    while process.isRunning {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { return false }
        RunLoop.current.run(until: Date(timeIntervalSinceNow: min(0.02, remaining)))
    }
    return true
}

struct RegistrationIntake {
    let status: String, origin: String, message: String
    let root: String, stateDir: String, token: String
    let pendingCount: Int
    var monitor: String = ""
    var uiReasonCode: String? = nil
    var uiFailure: UIMessage? = nil
    var helperExitVerified = true
    static func hold(_ message: String) -> RegistrationIntake {
        RegistrationIntake(status: "HOLD", origin: "UNKNOWN", message: message,
                           root: "", stateDir: "", token: "", pendingCount: 0)
    }
    static func hold(_ explanation: UIMessage) -> RegistrationIntake {
        var value = hold(explanation.raw)
        value.uiFailure = explanation
        return value
    }
    var presentationMessage: UIMessage {
        if let uiFailure { return uiFailure }
        if let code = uiReasonCode, let key = registrationReasonKeys[code] {
            return UIM(key, message)
        }
        return UIM("registration.generic_hold", message)
    }

    var notice: String {
        switch origin {
        case "R2": return "公開版の登録を引き継ぎました。未確認変更・承認履歴は元の保存先に保持しています。監視開始は手動です。"
        case "PREVIEW11": return "確認した登録を引き継ぎました。元の保存先と未確認変更を保持しています。監視開始は手動です。"
        case "CURRENT": return "保存済みの登録を確認しました。監視は手動で開始してください。"
        default: return "フォルダ登録後、明示的に監視を開始してください。"
        }
    }

    var presentationNotice: UIMessage {
        switch origin {
        case "R2": return UIM("registration.notice.r2", "公開版の登録を引き継ぎました。未確認変更・承認履歴は元の保存先に保持しています。監視開始は手動です。")
        case "PREVIEW11": return UIM("registration.notice.preview", "確認した登録を引き継ぎました。元の保存先と未確認変更を保持しています。監視開始は手動です。")
        case "CURRENT": return UIM("registration.notice.current", "保存済みの登録を確認しました。監視は手動で開始してください。")
        case "SWITCH": return UIM("registration.switch.done", "監視先を変更しました。前の監視記録は保存されています。新しい監視先は停止中です。")
        default: return UIM("monitor.register_first", "フォルダ登録後、明示的に監視を開始してください。")
        }
    }
}

func registrationContinuity(_ action: String, path: String, expected: String? = nil,
                            root: String? = nil, stateDir: String? = nil, ownedPID: Int32? = nil,
                            runToken: String? = nil, newRoot: String? = nil, newStateDir: String? = nil,
                            reviewedSnapshot: String? = nil, waitForReviewLock: Bool = false) -> RegistrationIntake {
    guard let runtime = try? SentinelRuntime.load(),
          SentinelRuntime.validates(python: runtime.python, script: runtime.continuity) else {
        return .hold(UIM("registration.helper_invalid", "同梱の登録検証処理を確認できません。既存の登録は変更していません。"))
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: runtime.python)
    var arguments = ["-I", "-S", "-B", runtime.continuity, action, "--registration-file", path]
    if let expected { arguments += ["--expected", expected] }
    if let root { arguments += ["--root", root] }
    if let stateDir { arguments += ["--state-dir", stateDir] }
    if let ownedPID { arguments += ["--owned-pid", String(ownedPID), "--owner-pid", String(getpid())] }
    if let runToken { arguments += ["--run-token", runToken] }
    if let newRoot { arguments += ["--new-root", newRoot] }
    if let newStateDir { arguments += ["--new-state-dir", newStateDir] }
    if let reviewedSnapshot { arguments += ["--reviewed-snapshot", reviewedSnapshot] }
    if waitForReviewLock { arguments.append("--wait-review-lock") }
    process.arguments = arguments; process.environment = SentinelRuntime.environment
    let pipe = Pipe(), diagnostics = Pipe()
    process.standardOutput = pipe; process.standardError = diagnostics
    do { try process.run() } catch { return .hold(UIM("registration.helper_start", "登録検証処理を起動できません。既存の記録は保持しています。")) }
    if !registrationExit(process, within: 3) {
        process.terminate()
        if !registrationExit(process, within: 1), process.isRunning {
            _ = Darwin.kill(process.processIdentifier, SIGKILL); _ = registrationExit(process, within: 1)
        }
        let fd = diagnostics.fileHandleForReading.fileDescriptor
        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        var bytes = [UInt8](repeating: 0, count: 2048)
        let size = Darwin.read(fd, &bytes, bytes.count)
        let raw = size > 0 ? String(decoding: bytes.prefix(size), as: UTF8.self) : ""
        let phases = Set(["START", "REGISTRY", "STATE_SCHEMA", "READER_IMPORT", "READER_VALIDATE", "MONITOR_LEASE", "POINTER_PUBLISH", "DONE"])
        let phase = raw.split(separator: "\n").compactMap { line -> String? in
            let value = String(line).replacingOccurrences(of: "ORCHARD_CONTINUITY_PHASE:", with: "")
            return phases.contains(value) ? value : nil
        }.last ?? "START_UNKNOWN"
        var hold = RegistrationIntake.hold(UIM("registration.timeout_prefix", "登録検証が時間内に完了しませんでした（") + phase + UIM("registration.timeout_suffix", "）。既存記録は保持しています。アプリを終了して問い合わせてください。"))
        hold.helperExitVerified = !process.isRunning
        return hold
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0, data.count <= 16_384,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let status = value["status"] as? String, ["READY", "UNREGISTERED", "CHOICE", "HOLD"].contains(status) else {
        return .hold(UIM("registration.helper_result", "登録検証の結果を確認できません。既存の記録は保持しています。"))
    }
    let selectedRoot = value["root"] as? String ?? "", selectedState = value["state_dir"] as? String ?? ""
    if ["READY", "CHOICE"].contains(status) && (selectedRoot.isEmpty || selectedState.isEmpty) {
        return .hold(UIM("registration.helper_missing_path", "登録検証の結果に保存先がありません。既存の記録は保持しています。"))
    }
    return RegistrationIntake(status: status, origin: value["origin"] as? String ?? "UNKNOWN",
        message: value["message"] as? String ?? "", root: selectedRoot, stateDir: selectedState,
        token: value["registration_SHA256"] as? String ?? "", pendingCount: value["pending_count"] as? Int ?? 0,
        monitor: value["monitor"] as? String ?? "",
        uiReasonCode: value["reason"] as? String)
}
