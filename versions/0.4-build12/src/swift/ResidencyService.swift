import Foundation
import CoreFoundation
import Darwin
import ServiceManagement

enum SentinelResidencyBuild {
    // No runtime argument, preference or watched content can open this build gate.
    static let activationAllowed = false // Unconditional; no build flag can register.
    static let mainID = "local.orchard.oss"
    static let helperID = "local.orchard.oss.loginhelper"
    static var registrationPath: String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Orchard/registration.json").path
    }
}

enum SentinelRegistration: String {
    case enabled = "ENABLED", requiresApproval = "REQUIRES_APPROVAL"
    case notRegistered = "NOT_REGISTERED", notFound = "NOT_FOUND", unknown = "UNKNOWN"
    var japanese: String {
        switch self {
        case .enabled: return "登録済み（起動可能・監視稼働は別）"
        case .requiresApproval: return "macOSの承認待ち"
        case .notRegistered: return "未登録"
        case .notFound: return "サービスが見つからない"
        case .unknown: return "未確認"
        }
    }
}

@available(macOS 13.0, *)
@MainActor final class SentinelLoginService {
    private let service = SMAppService.loginItem(identifier: SentinelResidencyBuild.helperID)
    var status: SentinelRegistration {
        // Always read the OS. A saved desired_login flag is not registration.
        switch service.status {
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notRegistered: return .notRegistered
        case .notFound: return .notFound
        @unknown default: return .unknown
        }
    }
    func register() throws {
        guard SentinelResidencyBuild.activationAllowed else {
            throw NSError(domain: "SentinelResidencyGate", code: 1)
        }
        switch status {
        case .enabled, .requiresApproval: return // never repeat registration to infer approval
        case .notRegistered: try service.register()
        case .notFound, .unknown: throw NSError(domain: "SentinelServiceUnavailable", code: 2)
        }
    }
    func unregister(completion: @escaping (Bool) -> Void) {
        guard SentinelResidencyBuild.activationAllowed else { completion(false); return }
        if status == .notRegistered { completion(true); return }
        // Completion is used because synchronous unregister does not wait for reaping.
        service.unregister { error in
            let succeeded = error == nil
            DispatchQueue.main.async { completion(succeeded) }
        }
    }
}

func sentinelPrivateObject(_ path: String, limit: Int = 16_384) -> [String: Any]? {
    let parent = URL(fileURLWithPath: path).deletingLastPathComponent().path
    var directory = stat()
    guard lstat(parent, &directory) == 0,
          directory.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
          directory.st_uid == getuid(), directory.st_mode & 0o077 == 0 else { return nil }
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { return nil }
    defer { _ = close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
          info.st_uid == getuid(), info.st_mode & 0o077 == 0,
          info.st_size >= 0, info.st_size <= limit else { return nil }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
    guard let data = try? handle.read(upToCount: limit + 1), data.count <= limit,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    return value
}

struct SentinelPolicyView {
    let desiredLogin: Bool
    let desiredMonitor: Bool
    let reason: String
    var japaneseReason: String {
        switch reason {
        case "CRASH_LOOP": return "異常終了が続いたため自動復旧を停止"
        case "CLOCK_CHANGED": return "時刻を確認できないため自動復旧を停止"
        case "USER_PAUSE": return "利用者が監視を停止"
        case "USER_QUIT": return "利用者が監視を停止してアプリを終了"
        case "EXPLICIT_DISABLE": return "利用者がログイン登録の解除を選択"
        case "OS_DISABLED": return "macOSの登録状態が有効でないため自動監視を停止"
        case "INVALID_POLICY_PAUSED": return "保存状態を確認できず停止"
        case "EXPLICIT_ENABLE", "EXPLICIT_RESUME": return "利用者の明示選択を保存済み（稼働証明は別）"
        default: return "常駐は未選択"
        }
    }
}

func sentinelPolicy(root: String, stateDir: String) -> SentinelPolicyView? {
    guard let value = sentinelPrivateObject(stateDir + "/residency.json"),
          let version = value["version"] as? NSNumber, version.intValue == 1,
          CFGetTypeID(version) != CFBooleanGetTypeID(),
          value["root"] as? String == root,
          let login = value["desired_login"] as? NSNumber,
          let monitor = value["desired_monitor"] as? NSNumber,
          CFGetTypeID(login) == CFBooleanGetTypeID(), CFGetTypeID(monitor) == CFBooleanGetTypeID(),
          let reason = value["reason"] as? String,
          Set(["OFF", "EXPLICIT_ENABLE", "EXPLICIT_RESUME", "USER_PAUSE", "USER_QUIT",
               "EXPLICIT_DISABLE", "CRASH_LOOP", "CLOCK_CHANGED", "OS_DISABLED", "INVALID_POLICY_PAUSED"]).contains(reason),
          let last = value["last_event_epoch"] as? NSNumber,
          CFGetTypeID(last) != CFBooleanGetTypeID(), last.doubleValue.isFinite,
          last.doubleValue >= 0, last.doubleValue <= Date().timeIntervalSince1970,
          let budgets = value["budgets"] as? [String: Any],
          Set(budgets.keys) == Set(["helper", "owner", "watcher"]),
          !monitor.boolValue || login.boolValue else { return nil }
    for kind in ["helper", "owner", "watcher"] {
        guard let entries = budgets[kind] as? [NSNumber], entries.count <= 3 else { return nil }
        var previous = 0.0
        for entry in entries {
            let stamp = entry.doubleValue
            guard CFGetTypeID(entry) != CFBooleanGetTypeID(), stamp.isFinite,
                  stamp >= previous, stamp <= last.doubleValue else { return nil }
            previous = stamp
        }
    }
    return SentinelPolicyView(desiredLogin: login.boolValue,
                              desiredMonitor: monitor.boolValue, reason: reason)
}

func sentinelResidencyCommand(python: String, script: String, root: String,
                             stateDir: String, action: String,
                             arguments: [String] = []) -> [String: Any]? {
    guard SentinelRuntime.validates(python: python, script: script) else { return nil }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: python)
    process.arguments = ["-I", "-S", "-B", script, action, "--root", root,
                         "--state-dir", stateDir] + arguments
    process.environment = SentinelRuntime.environment
    let output = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    let done = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in done.signal() }
    do { try process.run() } catch { return nil }
    if done.wait(timeout: .now() + 3) == .timedOut {
        process.terminate()
        if done.wait(timeout: .now() + 1) == .timedOut, process.isRunning {
            _ = Darwin.kill(process.processIdentifier, SIGKILL)
            _ = done.wait(timeout: .now() + 1)
        }
        return nil
    }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0, data.count <= 16_384,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    return value
}
