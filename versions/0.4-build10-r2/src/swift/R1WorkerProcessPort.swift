// A9 product source: bounded direct child/FD transport. No app launch or native
// Sandbox qualification is implied by an offline test process using this file.
import Foundation
import CryptoKit
import Darwin

enum R1WorkerPortFault: String, Error {
    case reused, binding, pipe, spawn, process, input, output, receipt, cancelled
}

// The main thread requests cancellation; only the direct-child owner sends
// signals and waitpids. No PID is handed to a second concurrent reaper.
final class R1WorkerCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var reason: String?
    func request(_ value: String) {
        lock.lock(); defer { lock.unlock() }
        if reason == nil { reason = value }
    }
    var requested: Bool { lock.lock(); defer { lock.unlock() }; return reason != nil }
}

struct R1WorkerRuntime {
    let executable: URL
    let argvTail: [String]
    let environment: [String: String]
    let engine: URL?
    let expectedExecutableSHA256: String?
    let label: String
    private let validateFreshAtUse: (() throws -> Void)?

    init(executable: URL, argvTail: [String], environment: [String: String], engine: URL?,
         expectedExecutableSHA256: String?, label: String,
         validateFreshAtUse: (() throws -> Void)? = nil) {
        self.executable = executable; self.argvTail = argvTail; self.environment = environment
        self.engine = engine; self.expectedExecutableSHA256 = expectedExecutableSHA256
        self.label = label; self.validateFreshAtUse = validateFreshAtUse
    }

    static let a1EngineSHA256 = "1b4a89d5bf288b1be4fa188bad98a57637c6eacdd8f55f12d5dc385ded74b7a6"
    static let a8WorkerSHA256 = "5f29f3fe8fd11aa832a5ec69a9fe091bd6a790040b3802373b11d65907f83b4c"

    // Only a future separately admitted native composition may execute this
    // bundle layout. A9 verifies its source/manifest but never runs this ID.
    static func a8Bundled(in app: URL) -> R1WorkerRuntime {
        let contents = app.appendingPathComponent("Contents", isDirectory: true)
        let worker = contents.appendingPathComponent("MacOS/OrchardZipWorker")
        let engine = contents.appendingPathComponent("Resources/OrchardZipWorker/engine/zip_inspector.py")
        return R1WorkerRuntime(executable: worker,
            argvTail: ["-P", "-S", "-B", engine.path, "--fd", "0"],
            environment: ["PATH": "/usr/bin:/bin", "LC_ALL": "C",
                "PYTHONHOME": contents.appendingPathComponent("Resources/OrchardZipWorker").path,
                "PYTHONPATH": contents.appendingPathComponent("Frameworks").path],
            engine: engine, expectedExecutableSHA256: a8WorkerSHA256,
            label: "A8_SIGNED_BUNDLE_REQUIRES_NEW_NATIVE_QUALIFICATION")
    }

    func validateBeforeSpawn() throws {
        try validateFreshAtUse?()
        guard executable.isFileURL, executable.path.hasPrefix("/"),
              argvTail.count >= 2, argvTail.count <= 8,
              environment["PATH"] == "/usr/bin:/bin", environment["LC_ALL"] == "C",
              FileManager.default.isExecutableFile(atPath: executable.path) else { throw R1WorkerPortFault.binding }
        if let engine {
            let raw = try Data(contentsOf: engine)
            guard hash54(raw) == Self.a1EngineSHA256 else { throw R1WorkerPortFault.binding }
        }
        if let expectedExecutableSHA256 {
            let raw = try Data(contentsOf: executable)
            guard hash54(raw) == expectedExecutableSHA256 else { throw R1WorkerPortFault.binding }
        }
        try validateFreshAtUse?()
    }
}

private struct R1ProcessIdentity: Equatable {
    let pid: Int32
    let ppid: Int32
    let uid: UInt32
    let startSec: UInt64
    let startUsec: UInt64
    let path: String
    var json: [String: Any] {
        ["pid": Int(pid), "ppid": Int(ppid), "uid": Int(uid),
         "start_sec": Int(startSec), "start_usec": Int(startUsec), "path": path]
    }
}

private func r1ProcessIdentity(_ pid: pid_t) -> R1ProcessIdentity? {
    var info = proc_bsdinfo()
    let count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
    guard count == Int32(MemoryLayout<proc_bsdinfo>.size), info.pbi_pid == pid else { return nil }
    var path = [CChar](repeating: 0, count: 4096)
    guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
    return R1ProcessIdentity(pid: pid, ppid: Int32(info.pbi_ppid), uid: UInt32(info.pbi_uid),
                             startSec: UInt64(info.pbi_start_tvsec), startUsec: UInt64(info.pbi_start_tvusec),
                             path: String(cString: path))
}

private func r1SHA(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

final class R1WorkerProcessPort {
    private(set) var starts = 0
    private var consumed = false
    private var childReaped = true
    private var pipesClosed = true
    private var ownedPID: pid_t?
    var resourcesQuiescent: Bool { childReaped && pipesClosed }
    var resourceReadback: [String: Any] {
        ["pid": ownedPID.map { Int($0) } as Any? ?? NSNull(), "direct_child_reaped": childReaped,
         "owned_pipe_fds_closed": pipesClosed, "starts": starts]
    }
    let runtime: R1WorkerRuntime
    init(runtime: R1WorkerRuntime) { self.runtime = runtime }

    // Direct child only. Source bytes are read from the pinned B8 owned-copy FD;
    // archive text never enters argv or environment.
    func runOnce(inputFD: Int32, inputBytes: Int64, inputSHA256: String,
                 deadline: Double = 5.0, sendBytes: Int64? = nil,
                 holdInputOpen: Bool = false, cancellation: R1WorkerCancellation? = nil,
                 processEvent: (([String: Any]) throws -> Void)? = nil) throws -> Data {
        guard !consumed else { throw R1WorkerPortFault.reused }
        consumed = true
        guard inputFD >= 0, inputBytes > 0, inputBytes <= 8_388_608,
              inputSHA256.utf8.count == 64, deadline >= 0.2, deadline <= 10.0,
              sendBytes.map({ $0 >= 0 && $0 <= inputBytes }) ?? true else { throw R1WorkerPortFault.binding }
        let sendLimit = sendBytes ?? inputBytes
        guard cancellation?.requested != true else { throw R1WorkerPortFault.cancelled }
        try runtime.validateBeforeSpawn()

        var inputPipe: [Int32] = [-1, -1], outputPipe: [Int32] = [-1, -1], errorPipe: [Int32] = [-1, -1]
        guard pipe(&inputPipe) == 0 else { throw R1WorkerPortFault.pipe }
        guard pipe(&outputPipe) == 0 else {
            _ = close(inputPipe[0]); _ = close(inputPipe[1]); throw R1WorkerPortFault.pipe
        }
        guard pipe(&errorPipe) == 0 else {
            for fd in inputPipe + outputPipe { _ = close(fd) }; throw R1WorkerPortFault.pipe
        }
        let created = inputPipe + outputPipe + errorPipe
        pipesClosed = false
        var openFDs = Set(created)
        func closeOwned(_ fd: Int32) {
            if openFDs.remove(fd) != nil { _ = Darwin.close(fd) }
        }
        defer {
            for fd in Array(openFDs) { closeOwned(fd) }
            pipesClosed = created.allSatisfy { fd in
                errno = 0; return fcntl(fd, F_GETFD) == -1 && errno == EBADF
            }
        }
        // A worker that closes stdin must produce an EPIPE/HOLD, never kill
        // the AppKit parent before its owned FDs and child can be reclaimed.
        guard fcntl(inputPipe[1], F_SETNOSIGPIPE, 1) == 0 else { throw R1WorkerPortFault.pipe }
        var attributes: posix_spawnattr_t? = nil
        guard posix_spawnattr_init(&attributes) == 0 else { throw R1WorkerPortFault.spawn }
        defer { posix_spawnattr_destroy(&attributes) }
        // Only explicit file actions may expose descriptors to this child.
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw R1WorkerPortFault.spawn
        }
        var actions: posix_spawn_file_actions_t? = nil
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw R1WorkerPortFault.spawn }
        defer { posix_spawn_file_actions_destroy(&actions) }
        let actionCodes = [
            posix_spawn_file_actions_adddup2(&actions, inputPipe[0], STDIN_FILENO),
            posix_spawn_file_actions_adddup2(&actions, outputPipe[1], STDOUT_FILENO),
            posix_spawn_file_actions_adddup2(&actions, errorPipe[1], STDERR_FILENO)
        ] + created.map { posix_spawn_file_actions_addclose(&actions, $0) }
        guard actionCodes.allSatisfy({ $0 == 0 }) else { throw R1WorkerPortFault.spawn }
        let argvStrings = [runtime.executable.path] + runtime.argvTail
        let envStrings = runtime.environment.keys.sorted().map { $0 + "=" + runtime.environment[$0]! }
        let argvPointers = argvStrings.map { strdup($0) }
        let envPointers = envStrings.map { strdup($0) }
        defer { for p in argvPointers + envPointers { free(p) } }
        var argv = argvPointers + [nil]
        var env = envPointers + [nil]
        var pid: pid_t = 0
        guard cancellation?.requested != true else { throw R1WorkerPortFault.cancelled }
        let spawnCode = runtime.executable.path.withCString { path in
            argv.withUnsafeMutableBufferPointer { ap in
                env.withUnsafeMutableBufferPointer { ep in
                    posix_spawn(&pid, path, &actions, &attributes, ap.baseAddress, ep.baseAddress)
                }
            }
        }
        guard spawnCode == 0, pid > 0 else { throw R1WorkerPortFault.spawn }
        starts += 1
        ownedPID = pid; childReaped = false
        var evidenceFailure: String?
        do { try processEvent?(["phase": "SPAWNED", "pid": Int(pid), "parent_pid": Int(getpid()),
                               "worker_path": runtime.executable.path]) }
        catch { evidenceFailure = "PROCESS_EVIDENCE_WRITE_FAILED" }
        closeOwned(inputPipe[0]); closeOwned(outputPipe[1]); closeOwned(errorPipe[1])
        for fd in [inputPipe[1], outputPipe[0], errorPipe[0]] {
            let old = fcntl(fd, F_GETFL)
            guard old >= 0, fcntl(fd, F_SETFL, old | O_NONBLOCK) == 0 else {
                // The direct child still belongs to this call. Keep emergency
                // stop bounded even when nonblocking FD setup itself fails.
                _ = kill(pid, SIGTERM)
                var emergency = Int32(0), emergencyReaped = false
                let termEnd = ProcessInfo.processInfo.systemUptime + 0.5
                while ProcessInfo.processInfo.systemUptime < termEnd {
                    if waitpid(pid, &emergency, WNOHANG) == pid { emergencyReaped = true; break }
                    usleep(10_000)
                }
                if !emergencyReaped {
                    _ = kill(pid, SIGKILL)
                    let killEnd = ProcessInfo.processInfo.systemUptime + 1.0
                    while ProcessInfo.processInfo.systemUptime < killEnd {
                        if waitpid(pid, &emergency, WNOHANG) == pid { emergencyReaped = true; break }
                        usleep(10_000)
                    }
                }
                childReaped = emergencyReaped
                try? processEvent?(["phase": "EMERGENCY_STOP", "pid": Int(pid), "reaped": emergencyReaped])
                throw R1WorkerPortFault.process
            }
        }
        var firstIdentity: R1ProcessIdentity?
        for _ in 0..<50 {
            firstIdentity = r1ProcessIdentity(pid)
            if firstIdentity != nil { break }
            usleep(5_000)
        }
        let allowedPaths = Set([runtime.executable.path,
                                URL(fileURLWithPath: runtime.executable.path).resolvingSymlinksInPath().path])
        let identityValid = firstIdentity.map { $0.ppid == getpid() && $0.uid == getuid()
            && $0.startSec > 0 && allowedPaths.contains($0.path) } == true
        do { try processEvent?(["phase": "IDENTITY", "pid": Int(pid),
                "identity": firstIdentity?.json ?? [:], "observed": identityValid]) }
        catch { evidenceFailure = "PROCESS_IDENTITY_EVIDENCE_WRITE_FAILED" }
        var stdout = Data(), stderr = Data(), inputHasher = SHA256()
        var bytesWritten: Int64 = 0
        var pending = Data(), pendingOffset = 0
        var status: Int32 = 0, reaped = false
        var reason: String? = evidenceFailure
        var signals = [String]()
        var preSignalIdentity: R1ProcessIdentity?
        var preSignalMatch: Bool? = nil
        let began = ProcessInfo.processInfo.systemUptime
        func closeInputIfDone() {
            if bytesWritten == sendLimit && pending.isEmpty && !holdInputOpen { closeOwned(inputPipe[1]) }
        }
        while !reaped || openFDs.contains(outputPipe[0]) || openFDs.contains(errorPipe[0]) {
            if cancellation?.requested == true { reason = "CANCELLED_BY_OPERATION_OWNER" }
            if reason != nil { break }
            if !reaped {
                let found = waitpid(pid, &status, WNOHANG)
                if found == pid { reaped = true }
                else if found < 0 { reason = "WAITPID_ERROR"; break }
            }
            if reaped { closeOwned(inputPipe[1]) }
            let elapsed = ProcessInfo.processInfo.systemUptime - began
            if elapsed >= deadline && !reaped { reason = "TIMEOUT"; break }
            if elapsed > deadline + 2 { reason = "DRAIN_TIMEOUT"; break }
            if openFDs.contains(inputPipe[1]) && bytesWritten < sendLimit && pending.isEmpty {
                let want = Int(min(65_536, sendLimit - bytesWritten))
                var buffer = [UInt8](repeating: 0, count: want)
                let got = buffer.withUnsafeMutableBytes { pread(inputFD, $0.baseAddress, want, off_t(bytesWritten)) }
                if got <= 0 { reason = "PINNED_INPUT_READ"; break }
                pending = Data(buffer.prefix(got)); pendingOffset = 0
            }
            closeInputIfDone()
            var pollFDs = [pollfd]()
            if openFDs.contains(inputPipe[1]) && !pending.isEmpty {
                pollFDs.append(pollfd(fd: inputPipe[1], events: Int16(POLLOUT | POLLERR | POLLHUP), revents: 0))
            }
            if openFDs.contains(outputPipe[0]) {
                pollFDs.append(pollfd(fd: outputPipe[0], events: Int16(POLLIN | POLLERR | POLLHUP), revents: 0))
            }
            if openFDs.contains(errorPipe[0]) {
                pollFDs.append(pollfd(fd: errorPipe[0], events: Int16(POLLIN | POLLERR | POLLHUP), revents: 0))
            }
            let pollCode = pollFDs.withUnsafeMutableBufferPointer { ptr in
                poll(ptr.baseAddress, nfds_t(ptr.count), 20)
            }
            if pollCode < 0 && errno != EINTR { reason = "POLL_ERROR"; break }
            for row in pollFDs where row.revents != 0 {
                if row.fd == inputPipe[1] {
                    if (row.revents & Int16(POLLOUT)) != 0 {
                        let wrote = pending.withUnsafeBytes { raw -> Int in
                            Darwin.write(row.fd, raw.baseAddress!.advanced(by: pendingOffset), pending.count - pendingOffset)
                        }
                        if wrote > 0 {
                            inputHasher.update(data: pending.subdata(in: pendingOffset..<(pendingOffset + wrote)))
                            bytesWritten += Int64(wrote); pendingOffset += wrote
                            if pendingOffset == pending.count { pending = Data(); pendingOffset = 0 }
                        } else if wrote < 0 && errno != EAGAIN && errno != EINTR {
                            closeOwned(inputPipe[1])
                        }
                    } else if (row.revents & Int16(POLLERR | POLLHUP)) != 0 { closeOwned(inputPipe[1]) }
                } else {
                    var buffer = [UInt8](repeating: 0, count: 8192)
                    let capacity = buffer.count
                    let got = buffer.withUnsafeMutableBytes { Darwin.read(row.fd, $0.baseAddress, capacity) }
                    if got > 0 {
                        if row.fd == outputPipe[0] { stdout.append(contentsOf: buffer.prefix(got)) }
                        else { stderr.append(contentsOf: buffer.prefix(got)) }
                        if stdout.count > 1_048_576 || stderr.count > 16_384 { reason = "OUTPUT_LIMIT"; break }
                    } else if got == 0 { closeOwned(row.fd) }
                    else if errno != EAGAIN && errno != EINTR { reason = "PIPE_READ_ERROR"; break }
                }
            }
            if reason != nil { break }
        }
        if !reaped {
            let found = waitpid(pid, &status, WNOHANG)
            if found == pid { reaped = true }
            else if found == 0 {
                preSignalIdentity = r1ProcessIdentity(pid)
                if let firstIdentity, let preSignalIdentity {
                    preSignalMatch = firstIdentity.pid == preSignalIdentity.pid
                        && firstIdentity.ppid == preSignalIdentity.ppid
                        && firstIdentity.uid == preSignalIdentity.uid
                        && firstIdentity.startSec == preSignalIdentity.startSec
                        && firstIdentity.startUsec == preSignalIdentity.startUsec
                } else { preSignalMatch = false }
                // waitpid=0 means this exact direct child has not been reaped;
                // its PID cannot have been reassigned, even if path observation failed.
                if kill(pid, SIGTERM) == 0 { signals.append("TERM") }
                let end = ProcessInfo.processInfo.systemUptime + 0.5
                while ProcessInfo.processInfo.systemUptime < end {
                    let w = waitpid(pid, &status, WNOHANG)
                    if w == pid { reaped = true; break }
                    if w < 0 { break }
                    usleep(10_000)
                }
                if !reaped {
                    if kill(pid, SIGKILL) == 0 { signals.append("KILL") }
                    let killEnd = ProcessInfo.processInfo.systemUptime + 1.0
                    while ProcessInfo.processInfo.systemUptime < killEnd {
                        let w = waitpid(pid, &status, WNOHANG)
                        if w == pid { reaped = true; break }
                        if w < 0 { break }
                        usleep(10_000)
                    }
                }
            }
        }
        closeOwned(inputPipe[1]); closeOwned(outputPipe[0]); closeOwned(errorPipe[0])
        childReaped = reaped
        let fdClosed = created.allSatisfy { fd in
            errno = 0; return fcntl(fd, F_GETFD) == -1 && errno == EBADF
        }
        let inputDigest = inputHasher.finalize().map { String(format: "%02x", $0) }.joined()
        let exited = reaped && status & 0x7f == 0
        let exitCode: Int? = exited ? Int(status >> 8) : nil
        let stdoutText = String(data: stdout, encoding: .ascii)
        var report: [String: Any]? = nil
        var jsonStatus = "NOT_EVALUATED"
        if reason == nil && stdoutText != nil, let object = try? JSONSerialization.jsonObject(with: stdout) as? [String: Any] {
            report = object
            let input = object["input"] as? [String: Any]
            let inspection = object["inspection_status"] as? String
            let injection = object["prompt_injection"] as? String
            let gate = object["gate"] as? String
            let valid = object["format"] as? String == "orchard-c-static-zip/1.0"
                && input?["bytes"] as? Int == Int(inputBytes)
                && input?["sha256"] as? String == inputSHA256
                && bytesWritten == inputBytes && inputDigest == inputSHA256
                && object["safety_proven"] as? Bool == false
                && object["authorizes_actions"] as? Bool == false
                && ["COMPLETE", "UNKNOWN"].contains(inspection ?? "")
                && ["DETECTED", "NOT_DETECTED", "UNINSPECTABLE"].contains(injection ?? "")
                && ["HOLD", "CAP"].contains(gate ?? "")
                && exitCode == (inspection == "UNKNOWN" ? 2 : 0)
                && (inspection != "UNKNOWN" || gate == "HOLD")
                && (injection != "DETECTED" || gate == "HOLD")
                && (injection != "NOT_DETECTED" || (inspection == "COMPLETE" && gate == "CAP"))
                && (injection != "UNINSPECTABLE" || inspection == "UNKNOWN")
            jsonStatus = valid ? "VALID" : "CONTRACT_MISMATCH"
            if !valid { report = nil }
        }
        if reason == nil && !reaped { reason = "NOT_REAPED" }
        let receipt: [String: Any] = [
            "schema": "orchard-r1-a2-child-outcome/1.0", "runtime_label": runtime.label,
            "pid": Int(pid), "parent_pid": Int(getpid()),
            "child_identity": firstIdentity?.json ?? NSNull(),
            "start_identity_valid": identityValid,
            "pre_signal_identity": preSignalIdentity?.json ?? NSNull(),
            "pre_signal_identity_match": preSignalMatch as Any? ?? NSNull(),
            "deadline_seconds": deadline, "input_bytes_written": Int(bytesWritten),
            "input_sha256_written": inputDigest, "input_bytes_expected": Int(inputBytes),
            "stdout_bytes": stdout.count, "stdout_sha256": r1SHA(stdout),
            "stdout_ascii": stdoutText ?? "", "stderr_bytes": stderr.count,
            "exit_code": exitCode as Any? ?? NSNull(), "raw_wait_status": reaped ? Int(status) : NSNull(),
            "stop_reason": reason as Any? ?? NSNull(), "stop_detail": ["signals": signals],
            "waitpid_reaped": reaped, "all_created_pipe_fds_closed": fdClosed,
            "created_fd_count": created.count, "json_status": jsonStatus,
            "engine_report": report as Any? ?? NSNull(), "parent_gate": "HOLD",
            "authorizes_actions": false, "app_sandbox_verified": false
        ]
        guard JSONSerialization.isValidJSONObject(receipt) else { throw R1WorkerPortFault.receipt }
        try processEvent?(["phase": "STOP_READBACK", "pid": Int(pid), "reaped": reaped,
                           "pipe_fds_closed": fdClosed, "stop_reason": reason as Any? ?? NSNull()])
        return try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
    }
}
