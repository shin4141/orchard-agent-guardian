// A12 offline synthetic extraction transaction. No native app entry calls it.
import Foundation
import Darwin

enum R1A12Fault: String, Error {
    case root, identity, format, state, file, write, readback, foreign, notRecoverable
}

struct R1A12Object: Codable, Equatable {
    let dev: Int64
    let ino: UInt64
    let uid: UInt32
    let mode: UInt32
    init(_ s: stat) {
        dev = Int64(s.st_dev); ino = UInt64(s.st_ino)
        uid = UInt32(s.st_uid); mode = UInt32(s.st_mode & 0o777)
    }
}

struct R1A12File: Codable, Equatable {
    let path: String
    let bytes: Int
    let sha256: String
}

struct R1A12Intent: Codable, Equatable {
    let schema: String
    let root: R1A12Object
    let ownerID: UUID
    let storeID: UUID
    let sessionID: UUID
    let jobID: UUID
    let intakeAttemptID: UUID
    let extractionAttemptID: UUID
    let actorID: UUID
    let inputSHA256: String
    let files: [R1A12File]
    init(root: R1A12Object, ownerID: UUID, storeID: UUID, sessionID: UUID,
         jobID: UUID, intakeAttemptID: UUID, extractionAttemptID: UUID,
         actorID: UUID, inputSHA256: String, files: [R1A12File]) {
        self.schema = "orchard-r1-a12-intent/1.0"
        self.root = root; self.ownerID = ownerID; self.storeID = storeID
        self.sessionID = sessionID; self.jobID = jobID
        self.intakeAttemptID = intakeAttemptID; self.extractionAttemptID = extractionAttemptID
        self.actorID = actorID; self.inputSHA256 = inputSHA256; self.files = files
    }
}

struct R1A12State: Codable {
    let schema: String
    let intentSHA256: String
    let folder: R1A12Object
    let phase: String
    let completionSHA256: String?
    init(intentSHA256: String, folder: R1A12Object, phase: String, completionSHA256: String?) {
        self.schema = "orchard-r1-a12-state/1.0"
        self.intentSHA256 = intentSHA256; self.folder = folder
        self.phase = phase; self.completionSHA256 = completionSHA256
    }
}

struct R1A12Completion: Codable {
    let schema: String
    let intentSHA256: String
    let extractionAttemptID: UUID
    let inputSHA256: String
    let files: [R1A12File]
    let allFilesReadBack: Bool
    let aiHandoffPerformed: Bool
    init(intentSHA256: String, extractionAttemptID: UUID, inputSHA256: String,
         files: [R1A12File]) {
        self.schema = "orchard-r1-a12-completion/1.0"
        self.intentSHA256 = intentSHA256; self.extractionAttemptID = extractionAttemptID
        self.inputSHA256 = inputSHA256; self.files = files
        self.allFilesReadBack = true; self.aiHandoffPerformed = false
    }
}

struct R1A12Envelope<T: Codable>: Codable {
    let payload: T
    let sha256: String
}

struct R1A12Assessment: Encodable {
    let schema = "orchard-r1-a12-assessment/1.0"
    let status: String
    let root: String
    let attemptID: UUID
    let folder: String?
    let statePhase: String?
    let completionPresent: Bool
    let filesVerified: Bool
    let ready: Bool
    let aiHandoffAllowed = false
    let cleanupAllowed: Bool
    let reason: String
}

struct R1A12Ready: Encodable {
    let schema = "orchard-r1-a12-ready/1.0"
    let root: String
    let attemptID: UUID
    let folder: String
    let files: [R1A12File]
    let status = "READY_AFTER_DURABLE_COMPLETION_AND_SHA_READBACK"
    let aiHandoffPerformed = false
    let aiHandoffAllowed = false
}

enum R1A12IO {
    static func canonical<T: Encodable>(_ value: T) throws -> Data {
        let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try e.encode(value)
    }
    static func envelope<T: Codable>(_ payload: T) throws -> Data {
        try canonical(R1A12Envelope(payload: payload, sha256: hash54(canonical(payload))))
    }
    static func decode<T: Codable>(_ type: T.Type, _ raw: Data) throws -> T {
        guard raw.count <= 32_768 else { throw R1A12Fault.format }
        let value = try JSONDecoder().decode(R1A12Envelope<T>.self, from: raw)
        guard try hash54(canonical(value.payload)) == value.sha256,
              (try canonical(value)) == raw else { throw R1A12Fault.format }
        return value.payload
    }
    static func object(_ fd: Int32, type: mode_t, mode: mode_t) throws -> R1A12Object {
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_mode & S_IFMT == type,
              s.st_uid == geteuid(), s.st_mode & 0o777 == mode else { throw R1A12Fault.identity }
        return R1A12Object(s)
    }
    static func openRoot(_ url: URL) throws -> Int32 {
        guard url.isFileURL && url.path.hasPrefix("/"), !url.path.utf8.contains(0) else { throw R1A12Fault.root }
        let fd = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard fd >= 0 else { throw R1A12Fault.root }
        do {
            let identity = try object(fd, type: S_IFDIR, mode: 0o700)
            var path = stat()
            guard lstat(url.path, &path) == 0, identity == R1A12Object(path) else { throw R1A12Fault.root }
            return fd
        } catch { _ = Darwin.close(fd); throw error }
    }
    static func openDir(_ parent: Int32, _ name: String) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw R1A12Fault.identity }
        do { _ = try object(fd, type: S_IFDIR, mode: 0o700); return fd }
        catch { _ = Darwin.close(fd); throw error }
    }
    static func put(_ dir: Int32, _ name: String, _ raw: Data) throws {
        let fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw R1A12Fault.write }
        do {
            var offset = 0
            while offset < raw.count {
                let n = raw.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), raw.count - offset) }
                guard n > 0 else { throw R1A12Fault.write }
                offset += n
            }
            guard fsync(fd) == 0 else { throw R1A12Fault.write }
        } catch { _ = Darwin.close(fd); throw error }
        _ = Darwin.close(fd)
        guard fsync(dir) == 0 else { throw R1A12Fault.write }
    }
    static func get(_ dir: Int32, _ name: String, cap: Int = 32_768) throws -> Data {
        let fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw R1A12Fault.file }
        defer { _ = Darwin.close(fd) }
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_mode & S_IFMT == S_IFREG,
              s.st_uid == geteuid(), s.st_nlink == 1,
              s.st_mode & 0o777 == 0o600, s.st_size >= 0,
              s.st_size <= cap else { throw R1A12Fault.identity }
        var bytes = Data()
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while bytes.count < Int(s.st_size) {
            let count = min(chunk.count, Int(s.st_size) - bytes.count)
            let n = chunk.withUnsafeMutableBytes { pread(fd, $0.baseAddress, count, off_t(bytes.count)) }
            guard n > 0 else { throw R1A12Fault.readback }
            bytes.append(contentsOf: chunk.prefix(n))
        }
        return bytes
    }
    static func exists(_ dir: Int32, _ name: String) -> Bool {
        var s = stat()
        return fstatat(dir, name, &s, AT_SYMLINK_NOFOLLOW) == 0
    }
    static func parentFD(_ payload: Int32, _ path: String) throws -> (Int32, String) {
        let parts = path.split(separator: "/").map(String.init)
        guard let leaf = parts.last else { throw R1A12Fault.format }
        var fd = dup(payload)
        guard fd >= 0 else { throw R1A12Fault.file }
        do {
            for part in parts.dropLast() {
                let next = try openDir(fd, part)
                _ = Darwin.close(fd); fd = next
            }
            return (fd, leaf)
        } catch { _ = Darwin.close(fd); throw error }
    }
    static func filesMatch(_ payload: Int32, _ files: [R1A12File]) -> Bool {
        for item in files {
            do {
                let (parent, leaf) = try parentFD(payload, item.path)
                defer { _ = Darwin.close(parent) }
                let raw = try get(parent, leaf, cap: item.bytes)
                guard raw.count == item.bytes, hash54(raw) == item.sha256 else { return false }
            } catch { return false }
        }
        return true
    }
    static func exactTree(_ payloadURL: URL, _ files: [R1A12File]) -> Bool {
        let expectedFiles = Set(files.map(\.path))
        var expectedDirs = Set<String>()
        for file in files {
            let parts = file.path.split(separator: "/").map(String.init)
            for n in 1..<parts.count { expectedDirs.insert(parts.prefix(n).joined(separator: "/")) }
        }
        guard let enumerator = FileManager.default.enumerator(at: payloadURL, includingPropertiesForKeys: nil) else { return false }
        var actualFiles = Set<String>(), actualDirs = Set<String>()
        for case let url as URL in enumerator {
            let relative = String(url.path.dropFirst(payloadURL.path.count + 1))
            var s = stat()
            guard lstat(url.path, &s) == 0, s.st_uid == geteuid() else { return false }
            if s.st_mode & S_IFMT == S_IFDIR && s.st_mode & 0o777 == 0o700 {
                actualDirs.insert(relative)
            } else if s.st_mode & S_IFMT == S_IFREG && s.st_mode & 0o777 == 0o600 && s.st_nlink == 1 {
                actualFiles.insert(relative)
            } else { return false }
        }
        return actualFiles == expectedFiles && actualDirs == expectedDirs
    }
}

enum R1A12Transaction {
    static func folderName(_ id: UUID) -> String { "r1-a12-" + id.uuidString.lowercased() }
    static func intentName(_ id: UUID) -> String { folderName(id) + ".intent.json" }
    static func closedName(_ id: UUID) -> String { folderName(id) + ".closed.json" }

    static func write(prepared: R1A11Prepared, root: URL, attemptID: UUID,
                      checkpoint: (String, URL) throws -> Void = { _, _ in }) throws -> R1A12Ready {
        let rootFD = try R1A12IO.openRoot(root)
        defer { _ = Darwin.close(rootFD) }
        let rootIdentity = try R1A12IO.object(rootFD, type: S_IFDIR, mode: 0o700)
        let b = prepared.binding
        let files = prepared.members.map { R1A12File(path: $0.path, bytes: $0.content.count, sha256: $0.sha256) }
        guard !files.isEmpty && files.count <= 32, Set(files.map(\.path)).count == files.count,
              files.allSatisfy({ !$0.path.isEmpty && $0.bytes <= 2_097_152 }) else { throw R1A12Fault.format }
        let intent = R1A12Intent(root: rootIdentity, ownerID: b.ownerID, storeID: b.storeID,
            sessionID: b.sessionID, jobID: b.jobID, intakeAttemptID: b.intakeAttemptID,
            extractionAttemptID: attemptID, actorID: prepared.actorID,
            inputSHA256: b.copiedZIPSHA256, files: files)
        let intentRaw = try R1A12IO.envelope(intent)
        let intentSHA = hash54(intentRaw)
        let name = folderName(attemptID)
        guard attemptID != b.intakeAttemptID, attemptID != b.sessionID,
              !R1A12IO.exists(rootFD, name),
              !R1A12IO.exists(rootFD, intentName(attemptID)),
              !R1A12IO.exists(rootFD, closedName(attemptID)) else { throw R1A12Fault.foreign }
        try R1A12IO.put(rootFD, intentName(attemptID), intentRaw)
        guard mkdirat(rootFD, name, 0o700) == 0 else { throw R1A12Fault.write }
        guard fsync(rootFD) == 0 else { throw R1A12Fault.write }
        let folderFD = try R1A12IO.openDir(rootFD, name)
        defer { _ = Darwin.close(folderFD) }
        let folderIdentity = try R1A12IO.object(folderFD, type: S_IFDIR, mode: 0o700)
        let state = R1A12State(intentSHA256: intentSHA, folder: folderIdentity,
                              phase: "PENDING", completionSHA256: nil)
        try R1A12IO.put(folderFD, "STATE.json", R1A12IO.envelope(state))
        guard mkdirat(folderFD, "payload", 0o700) == 0, fsync(folderFD) == 0 else { throw R1A12Fault.write }
        let payloadFD = try R1A12IO.openDir(folderFD, "payload")
        defer { _ = Darwin.close(payloadFD) }
        let folderURL = root.appendingPathComponent(name, isDirectory: true)
        try checkpoint("BEFORE_PAYLOAD", folderURL)

        var knownDirs = Set<String>()
        for (index, member) in prepared.members.enumerated() {
            let parts = member.path.split(separator: "/").map(String.init)
            var current = dup(payloadFD)
            guard current >= 0 else { throw R1A12Fault.write }
            defer { _ = Darwin.close(current) }
            var prefix = ""
            for part in parts.dropLast() {
                prefix += "/" + part
                if !knownDirs.contains(prefix) {
                    guard mkdirat(current, part, 0o700) == 0 else { throw R1A12Fault.write }
                    knownDirs.insert(prefix)
                }
                let next = try R1A12IO.openDir(current, part)
                _ = Darwin.close(current); current = next
            }
            guard let leaf = parts.last else { throw R1A12Fault.format }
            let fd = openat(current, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw R1A12Fault.write }
            let halfway = index == 0 ? member.content.count / 2 : member.content.count
            do {
                try writeBytes(fd, member.content, from: 0, to: halfway)
                guard fsync(fd) == 0, fsync(current) == 0 else { throw R1A12Fault.write }
                if index == 0 { try checkpoint("MID_PAYLOAD", folderURL) }
                try writeBytes(fd, member.content, from: halfway, to: member.content.count)
                guard fsync(fd) == 0 else { throw R1A12Fault.write }
            } catch { _ = Darwin.close(fd); throw error }
            _ = Darwin.close(fd)
            guard fsync(current) == 0 else { throw R1A12Fault.write }
        }
        guard R1A12IO.filesMatch(payloadFD, files), fsync(payloadFD) == 0 else { throw R1A12Fault.readback }
        let completion = R1A12Completion(intentSHA256: intentSHA, extractionAttemptID: attemptID,
                                         inputSHA256: b.copiedZIPSHA256, files: files)
        let completionRaw = try R1A12IO.envelope(completion)
        try R1A12IO.put(folderFD, "COMPLETION.json", completionRaw)
        try checkpoint("BEFORE_READY", folderURL)
        let readyState = R1A12State(intentSHA256: intentSHA, folder: folderIdentity,
                                   phase: "READY", completionSHA256: hash54(completionRaw))
        try R1A12IO.put(folderFD, "STATE.next.json", R1A12IO.envelope(readyState))
        guard renameat(folderFD, "STATE.next.json", folderFD, "STATE.json") == 0,
              fsync(folderFD) == 0, fsync(rootFD) == 0 else { throw R1A12Fault.write }
        let assessment = try R1A12Recovery.assess(root: root, attemptID: attemptID)
        guard assessment.ready && assessment.filesVerified else { throw R1A12Fault.readback }
        return R1A12Ready(root: root.path, attemptID: attemptID, folder: folderURL.path, files: files)
    }

    private static func writeBytes(_ fd: Int32, _ data: Data, from start: Int, to end: Int) throws {
        var position = start
        while position < end {
            let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: position), end - position) }
            guard n > 0 else { throw R1A12Fault.write }
            position += n
        }
    }
}

enum R1A12Recovery {
    private static func base(_ root: URL, _ attemptID: UUID) throws ->
        (Int32, R1A12Intent, String, Int32?, R1A12State?) {
        let rootFD = try R1A12IO.openRoot(root)
        do {
            let raw = try R1A12IO.get(rootFD, R1A12Transaction.intentName(attemptID))
            let intent = try R1A12IO.decode(R1A12Intent.self, raw)
            guard intent.schema == "orchard-r1-a12-intent/1.0",
                  intent.extractionAttemptID == attemptID,
                  intent.root == (try R1A12IO.object(rootFD, type: S_IFDIR, mode: 0o700)),
                  intent.actorID == intent.ownerID,
                  intent.files.count > 0 && intent.files.count <= 32 else { throw R1A12Fault.identity }
            let name = R1A12Transaction.folderName(attemptID)
            if !R1A12IO.exists(rootFD, name) { return (rootFD, intent, hash54(raw), nil, nil) }
            let folderFD = try R1A12IO.openDir(rootFD, name)
            do {
                if !R1A12IO.exists(folderFD, "STATE.json") { return (rootFD, intent, hash54(raw), folderFD, nil) }
                let state = try R1A12IO.decode(R1A12State.self, R1A12IO.get(folderFD, "STATE.json"))
                guard state.schema == "orchard-r1-a12-state/1.0",
                      state.intentSHA256 == hash54(raw),
                      state.folder == (try R1A12IO.object(folderFD, type: S_IFDIR, mode: 0o700)),
                      state.phase == "PENDING" || state.phase == "READY" else { throw R1A12Fault.state }
                return (rootFD, intent, hash54(raw), folderFD, state)
            } catch { _ = Darwin.close(folderFD); throw error }
        } catch { _ = Darwin.close(rootFD); throw error }
    }

    static func assess(root: URL, attemptID: UUID) throws -> R1A12Assessment {
        do { return try assessVerified(root: root, attemptID: attemptID) }
        catch {
            return R1A12Assessment(status: "HOLD_UNVERIFIED", root: root.path,
                attemptID: attemptID, folder: nil, statePhase: nil,
                completionPresent: false, filesVerified: false, ready: false,
                cleanupAllowed: false, reason: "IDENTITY_OR_RECORD_UNREADABLE_\(error)")
        }
    }

    private static func assessVerified(root: URL, attemptID: UUID) throws -> R1A12Assessment {
        let (rootFD, intent, intentSHA, folderMaybe, state) = try base(root, attemptID)
        defer { _ = Darwin.close(rootFD); if let fd = folderMaybe { _ = Darwin.close(fd) } }
        let folder = root.appendingPathComponent(R1A12Transaction.folderName(attemptID)).path
        guard let folderFD = folderMaybe else {
            return R1A12Assessment(status: "HOLD_INCOMPLETE", root: root.path,
                attemptID: attemptID, folder: nil, statePhase: nil,
                completionPresent: false, filesVerified: false, ready: false,
                cleanupAllowed: true, reason: "INTENT_DURABLE_FOLDER_ABSENT")
        }
        guard let state else {
            let empty = (try? FileManager.default.contentsOfDirectory(atPath: folder))?.isEmpty == true
            return R1A12Assessment(status: empty ? "HOLD_INCOMPLETE" : "HOLD_UNIDENTIFIED_FOLDER",
                root: root.path, attemptID: attemptID, folder: folder, statePhase: nil,
                completionPresent: false, filesVerified: false, ready: false,
                cleanupAllowed: empty, reason: empty ? "EMPTY_FOLDER_AFTER_DURABLE_INTENT" : "FOLDER_WITHOUT_IDENTITY_STATE")
        }
        let completionPresent = R1A12IO.exists(folderFD, "COMPLETION.json")
        let payloadPresent = R1A12IO.exists(folderFD, "payload")
        let filesVerified: Bool
        if payloadPresent {
            let payloadFD = try R1A12IO.openDir(folderFD, "payload")
            defer { _ = Darwin.close(payloadFD) }
            filesVerified = R1A12IO.filesMatch(payloadFD, intent.files) &&
                R1A12IO.exactTree(root.appendingPathComponent(R1A12Transaction.folderName(attemptID))
                    .appendingPathComponent("payload"), intent.files)
        } else { filesVerified = false }
        if state.phase == "PENDING" {
            return R1A12Assessment(status: "HOLD_INCOMPLETE", root: root.path,
                attemptID: attemptID, folder: folder, statePhase: state.phase,
                completionPresent: completionPresent, filesVerified: filesVerified,
                ready: false, cleanupAllowed: true,
                reason: "PENDING_IS_NEVER_PROMOTED_AFTER_RESTART")
        }
        guard let completionSHA = state.completionSHA256, completionPresent, payloadPresent else {
            return R1A12Assessment(status: "HOLD_INVALID_READY", root: root.path,
                attemptID: attemptID, folder: folder, statePhase: state.phase,
                completionPresent: completionPresent, filesVerified: filesVerified,
                ready: false, cleanupAllowed: false, reason: "MISSING_COMPLETION")
        }
        let raw = try R1A12IO.get(folderFD, "COMPLETION.json")
        let completion = try R1A12IO.decode(R1A12Completion.self, raw)
        let top = try FileManager.default.contentsOfDirectory(atPath: folder)
        let valid = hash54(raw) == completionSHA && completion.schema == "orchard-r1-a12-completion/1.0"
            && completion.intentSHA256 == intentSHA && completion.extractionAttemptID == attemptID
            && completion.inputSHA256 == intent.inputSHA256 && completion.files == intent.files
            && completion.allFilesReadBack && !completion.aiHandoffPerformed && filesVerified
            && Set(top) == Set(["STATE.json", "COMPLETION.json", "payload"])
        return R1A12Assessment(status: valid ? "READY_VERIFIED" : "HOLD_INVALID_READY",
            root: root.path, attemptID: attemptID, folder: folder, statePhase: state.phase,
            completionPresent: completionPresent, filesVerified: filesVerified,
            ready: valid, cleanupAllowed: false,
            reason: valid ? "STATE_COMPLETION_FILES_MATCH" : "READY_CONTRACT_MISMATCH")
    }

    static func cleanupIncomplete(root: URL, attemptID: UUID) throws -> R1A12Assessment {
        let assessment = try assess(root: root, attemptID: attemptID)
        guard assessment.status == "HOLD_INCOMPLETE", assessment.cleanupAllowed else { throw R1A12Fault.notRecoverable }
        let (rootFD, intent, _, folderMaybe, state) = try base(root, attemptID)
        defer { _ = Darwin.close(rootFD); if let fd = folderMaybe { _ = Darwin.close(fd) } }
        let name = R1A12Transaction.folderName(attemptID)
        if let folderFD = folderMaybe {
            if state == nil {
                let path = root.appendingPathComponent(name).path
                guard (try FileManager.default.contentsOfDirectory(atPath: path)).isEmpty,
                      unlinkat(rootFD, name, AT_REMOVEDIR) == 0 else { throw R1A12Fault.foreign }
            } else {
            guard let state, state.phase == "PENDING" else { throw R1A12Fault.notRecoverable }
            let payloadPresent = R1A12IO.exists(folderFD, "payload")
            let payload = payloadPresent ? try R1A12IO.openDir(folderFD, "payload") : -1
            defer { if payload >= 0 { _ = Darwin.close(payload) } }
            let allowed = Set(["STATE.json", "COMPLETION.json", "STATE.next.json", "payload"])
            let folderURL = root.appendingPathComponent(name)
            let top = try FileManager.default.contentsOfDirectory(atPath: folderURL.path)
            guard Set(top).isSubset(of: allowed) else { throw R1A12Fault.foreign }
            var dirs = Set<String>()
            let fileSet = Set(intent.files.map(\.path))
            for file in intent.files {
                let parts = file.path.split(separator: "/").map(String.init)
                for n in 1..<parts.count { dirs.insert(parts.prefix(n).joined(separator: "/")) }
            }
            var existingDirs = Set<String>()
            if payloadPresent {
                let payloadURL = folderURL.appendingPathComponent("payload")
                guard let enumerator = FileManager.default.enumerator(at: payloadURL, includingPropertiesForKeys: nil) else {
                    throw R1A12Fault.foreign
                }
                for case let url as URL in enumerator {
                    let relative = String(url.path.dropFirst(payloadURL.path.count + 1))
                    let s = try statPath(url)
                    guard s.st_uid == geteuid(),
                          (dirs.contains(relative) && s.st_mode & S_IFMT == S_IFDIR && s.st_mode & 0o777 == 0o700)
                            || (fileSet.contains(relative) && s.st_mode & S_IFMT == S_IFREG
                                && s.st_mode & 0o777 == 0o600 && s.st_nlink == 1
                                && s.st_size <= (intent.files.first { $0.path == relative }?.bytes ?? -1)) else {
                        throw R1A12Fault.foreign
                    }
                    if s.st_mode & S_IFMT == S_IFDIR { existingDirs.insert(relative) }
                }
            }
            for file in intent.files where payloadPresent {
                let parts = file.path.split(separator: "/").map(String.init)
                let parentPath = parts.dropLast().joined(separator: "/")
                if !parentPath.isEmpty && !existingDirs.contains(parentPath) { continue }
                let (parent, leaf) = try R1A12IO.parentFD(payload, file.path)
                defer { _ = Darwin.close(parent) }
                if R1A12IO.exists(parent, leaf) {
                    var s = stat()
                    guard fstatat(parent, leaf, &s, AT_SYMLINK_NOFOLLOW) == 0,
                          s.st_mode & S_IFMT == S_IFREG, s.st_uid == geteuid(),
                          s.st_mode & 0o777 == 0o600, s.st_nlink == 1,
                          s.st_size <= file.bytes,
                          unlinkat(parent, leaf, 0) == 0 else { throw R1A12Fault.foreign }
                }
            }
            for dir in existingDirs.sorted(by: { $0.split(separator: "/").count > $1.split(separator: "/").count }) {
                let (parent, leaf) = try R1A12IO.parentFD(payload, dir)
                defer { _ = Darwin.close(parent) }
                guard unlinkat(parent, leaf, AT_REMOVEDIR) == 0 else { throw R1A12Fault.foreign }
            }
            if payloadPresent {
                guard unlinkat(folderFD, "payload", AT_REMOVEDIR) == 0 else { throw R1A12Fault.foreign }
            }
            for file in ["STATE.next.json", "COMPLETION.json", "STATE.json"] where R1A12IO.exists(folderFD, file) {
                _ = try R1A12IO.get(folderFD, file)
                guard unlinkat(folderFD, file, 0) == 0 else { throw R1A12Fault.foreign }
            }
            guard fsync(folderFD) == 0 else { throw R1A12Fault.write }
            var s = stat()
            guard fstatat(rootFD, name, &s, AT_SYMLINK_NOFOLLOW) == 0,
                  R1A12Object(s) == state.folder,
                  unlinkat(rootFD, name, AT_REMOVEDIR) == 0 else { throw R1A12Fault.foreign }
            }
        }
        _ = try R1A12IO.get(rootFD, R1A12Transaction.intentName(attemptID))
        guard !R1A12IO.exists(rootFD, R1A12Transaction.closedName(attemptID)),
              renameat(rootFD, R1A12Transaction.intentName(attemptID),
                       rootFD, R1A12Transaction.closedName(attemptID)) == 0,
              fsync(rootFD) == 0 else { throw R1A12Fault.write }
        return assessment
    }

    private static func statPath(_ url: URL) throws -> stat {
        var s = stat()
        guard lstat(url.path, &s) == 0 else { throw R1A12Fault.foreign }
        return s
    }
}
