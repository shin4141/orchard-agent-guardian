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
    static func hold(_ message: String) -> RegistrationIntake {
        RegistrationIntake(status: "HOLD", origin: "UNKNOWN", message: message,
                           root: "", stateDir: "", token: "", pendingCount: 0)
    }
    var notice: String {
        switch origin {
        case "R2": return "公開版の登録を引き継ぎました。未確認変更・承認履歴は元の保存先に保持しています。監視開始は手動です。"
        case "PREVIEW11": return "確認した登録を引き継ぎました。元の保存先と未確認変更を保持しています。監視開始は手動です。"
        case "CURRENT": return "保存済みの登録を確認しました。監視は手動で開始してください。"
        default: return "フォルダ登録後、明示的に監視を開始してください。"
        }
    }
}

func registrationContinuity(_ action: String, path: String, expected: String? = nil,
                            root: String? = nil, stateDir: String? = nil,
                            ownedPID: Int32? = nil) -> RegistrationIntake {
    guard let runtime = try? SentinelRuntime.load(),
          SentinelRuntime.validates(python: runtime.python, script: runtime.continuity) else {
        return .hold("同梱の登録検証処理を確認できません。既存の登録は変更していません。")
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: runtime.python)
    var arguments = ["-I", "-S", "-B", runtime.continuity, action, "--registration-file", path]
    if let expected { arguments += ["--expected", expected] }
    if let root { arguments += ["--root", root] }
    if let stateDir { arguments += ["--state-dir", stateDir] }
    if let ownedPID { arguments += ["--owned-pid", String(ownedPID), "--owner-pid", String(getpid())] }
    process.arguments = arguments; process.environment = SentinelRuntime.environment
    let pipe = Pipe(), diagnostics = Pipe()
    process.standardOutput = pipe; process.standardError = diagnostics
    do { try process.run() } catch { return .hold("登録検証処理を起動できません。既存の記録は保持しています。") }
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
        return .hold("登録検証が時間内に完了しませんでした（" + phase + "）。既存記録は保持しています。アプリを終了して問い合わせてください。")
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0, data.count <= 16_384,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let status = value["status"] as? String, ["READY", "UNREGISTERED", "CHOICE", "HOLD"].contains(status) else {
        return .hold("登録検証の結果を確認できません。既存の記録は保持しています。")
    }
    let selectedRoot = value["root"] as? String ?? "", selectedState = value["state_dir"] as? String ?? ""
    if ["READY", "CHOICE"].contains(status) && (selectedRoot.isEmpty || selectedState.isEmpty) {
        return .hold("登録検証の結果に保存先がありません。既存の記録は保持しています。")
    }
    return RegistrationIntake(status: status, origin: value["origin"] as? String ?? "UNKNOWN",
        message: value["message"] as? String ?? "", root: selectedRoot, stateDir: selectedState,
        token: value["registration_SHA256"] as? String ?? "", pendingCount: value["pending_count"] as? Int ?? 0)
}
