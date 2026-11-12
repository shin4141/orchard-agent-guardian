// A11 offline qualification stays separate. The fresh product adapter below
// requires explicit native and exact extraction admission; it issues no GO.
import Foundation
import CryptoKit
import Darwin

enum R1A11Fault: String, Error {
    case scope, confirmation, expired, actor, identity, attempt, archive, path, type
    case limit, crc, destination, write, readback
}

struct R1A11File: Encodable {
    let path: String
    let bytes: Int
    let sha256: String
}

struct R1A11Receipt: Encodable {
    let schema = "orchard-r1-a11-offline-extraction/1.0"
    let ownerID: UUID
    let storeID: UUID
    let sessionID: UUID
    let jobID: UUID
    let inputSHA256: String
    let actorID: UUID
    let folderPath: String
    let files: [R1A11File]
    let status = "SYNTHETIC_FILES_READ_BACK"
    let untrustedSourceRole = "UNTRUSTED_ARCHIVE_DATA"
    let aiHandoffDescription = "File paths, sizes and SHA256 are available for a separately authorized future AI handoff. No AI request was made."
    let aiHandoffPerformed = false
    let authorizesAIHandoff = false
}

struct R1A11Member {
    let path: String
    let content: Data
    let sha256: String
}

struct R1A11Prepared {
    let binding: R1ProductBinding
    let actorID: UUID
    let members: [R1A11Member]
}

// Historical native/Session admissions do not implement this new interface.
protocol R1A11NativeExtractionAdmission: R1ProductNativeAdmission {
    func verifyLimitedExtraction(binding: R1ProductBinding, attemptID: UUID,
                                 destinationRoot: URL) throws
}

enum R1A11StoredZIP {
    private static func u16(_ b: [UInt8], _ p: Int) -> Int {
        guard p >= 0 && p <= b.count - 2 else { return -1 }
        return Int(b[p]) | Int(b[p + 1]) << 8
    }
    private static func u32(_ b: [UInt8], _ p: Int) -> Int {
        guard p >= 0 && p <= b.count - 4 else { return -1 }
        return Int(b[p]) | Int(b[p + 1]) << 8 | Int(b[p + 2]) << 16 | Int(b[p + 3]) << 24
    }
    private static func crc32(_ bytes: ArraySlice<UInt8>) -> Int {
        var crc: UInt32 = 0xffff_ffff
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc >> 1) ^ ((crc & 1) == 1 ? 0xedb8_8320 : 0) }
        }
        return Int(~crc)
    }
    private static func checkedName(_ bytes: ArraySlice<UInt8>) throws -> String {
        guard !bytes.isEmpty && bytes.count <= 256,
              bytes.allSatisfy({ (0x41...0x5a).contains($0) || (0x61...0x7a).contains($0) ||
                  (0x30...0x39).contains($0) || $0 == 0x2d || $0 == 0x5f ||
                  $0 == 0x2e || $0 == 0x2f }),
              let name = String(bytes: bytes, encoding: .ascii), !name.hasPrefix("/") else {
            throw R1A11Fault.path
        }
        let parts = name.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 8, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              !name.hasSuffix("/") else { throw R1A11Fault.path }
        return name
    }

    static func parse(_ data: Data) throws -> [R1A11Member] {
        let b = [UInt8](data)
        guard b.count >= 22 && b.count <= 8_388_608 else { throw R1A11Fault.limit }
        let end = b.count - 22
        guard u32(b, end) == 0x0605_4b50,
              u16(b, end + 4) == 0, u16(b, end + 6) == 0,
              u16(b, end + 8) == u16(b, end + 10),
              u16(b, end + 20) == 0 else { throw R1A11Fault.archive }
        let count = u16(b, end + 10)
        let centralBytes = u32(b, end + 12)
        let centralStart = u32(b, end + 16)
        guard count > 0 && count <= 32, centralStart <= end,
              centralBytes == end - centralStart else { throw R1A11Fault.limit }
        var cursor = centralStart
        var seen = Set<String>()
        var ranges = [(Int, Int)]()
        var members = [R1A11Member]()
        var totalOutput = 0
        for _ in 0..<count {
            guard cursor <= end - 46, u32(b, cursor) == 0x0201_4b50 else { throw R1A11Fault.archive }
            let flags = u16(b, cursor + 8)
            let method = u16(b, cursor + 10)
            let crc = u32(b, cursor + 16)
            let packed = u32(b, cursor + 20)
            let expanded = u32(b, cursor + 24)
            let nameLength = u16(b, cursor + 28)
            let extraLength = u16(b, cursor + 30)
            let commentLength = u16(b, cursor + 32)
            let disk = u16(b, cursor + 34)
            let mode = u32(b, cursor + 38) >> 16
            let local = u32(b, cursor + 42)
            guard flags == 0 || flags == 0x0800,
                  method == 0, packed == expanded,
                  packed <= 2_097_152, expanded <= 2_097_152,
                  extraLength == 0, commentLength == 0, disk == 0,
                  mode & Int(S_IFMT) == Int(S_IFREG),
                  nameLength > 0, nameLength <= 256,
                  cursor + 46 + nameLength <= end else { throw R1A11Fault.type }
            totalOutput += expanded
            guard totalOutput <= 4_194_304 else { throw R1A11Fault.limit }
            let nameBytes = b[(cursor + 46)..<(cursor + 46 + nameLength)]
            let name = try checkedName(nameBytes)
            let key = name.lowercased()
            guard !seen.contains(key), !seen.contains(where: { key.hasPrefix($0 + "/") || $0.hasPrefix(key + "/") }) else {
                throw R1A11Fault.path
            }
            seen.insert(key)
            guard local <= centralStart - 30, u32(b, local) == 0x0403_4b50,
                  u16(b, local + 6) == flags, u16(b, local + 8) == method,
                  u32(b, local + 14) == crc,
                  u32(b, local + 18) == packed, u32(b, local + 22) == expanded,
                  u16(b, local + 26) == nameLength,
                  u16(b, local + 28) == 0 else { throw R1A11Fault.archive }
            let dataStart = local + 30 + nameLength
            guard dataStart <= centralStart, packed <= centralStart - dataStart,
                  b[(local + 30)..<dataStart].elementsEqual(nameBytes) else { throw R1A11Fault.archive }
            let payload = b[dataStart..<(dataStart + packed)]
            guard crc32(payload) == crc else { throw R1A11Fault.crc }
            let content = Data(payload)
            members.append(R1A11Member(path: name, content: content,
                                       sha256: hash54(content)))
            ranges.append((local, dataStart + packed))
            cursor += 46 + nameLength
        }
        guard cursor == end else { throw R1A11Fault.archive }
        ranges.sort { $0.0 < $1.0 }
        var next = 0
        for (start, stop) in ranges {
            guard start == next && stop > start else { throw R1A11Fault.archive }
            next = stop
        }
        guard next == centralStart else { throw R1A11Fault.archive }
        return members
    }
}

@MainActor
final class R1A11OfflineExtractor {
    private var consumed = Set<UUID>()

    func extract(flow: R1ProductFlow, actorID: UUID, sessionID: UUID,
                 destinationRoot: URL) throws -> R1A11Receipt {
        let prepared = try prepare(flow: flow, actorID: actorID, sessionID: sessionID)
        let binding = prepared.binding
        let members = prepared.members
        let folder = try R1A11PrivateWriter.write(members, to: destinationRoot, jobID: binding.jobID)
        return R1A11Receipt(ownerID: binding.ownerID, storeID: binding.storeID,
                            sessionID: binding.sessionID, jobID: binding.jobID,
                            inputSHA256: binding.copiedZIPSHA256, actorID: actorID,
                            folderPath: folder.path,
                            files: members.map { R1A11File(path: $0.path, bytes: $0.content.count,
                                                            sha256: $0.sha256) })
    }

    // A12 uses this same receiver qualification before its durable writer.
    // Preparing consumes the attempt; restart cannot re-create the A3 review.
    func prepare(flow: R1ProductFlow, actorID: UUID, sessionID: UUID) throws -> R1A11Prepared {
        guard flow.owner.store.productOfflineQualification else { throw R1A11Fault.scope }
        return try prepareBoundCurrent(flow: flow, actorID: actorID, sessionID: sessionID)
    }

    // Called only by the separately admitted fresh composition. The offline
    // entry above still refuses a native store; no scope is relabelled offline.
    func prepareNative(flow: R1ProductFlow, actorID: UUID, sessionID: UUID,
                       attemptID: UUID, destinationRoot: URL,
                       admission: R1A11NativeExtractionAdmission) throws -> R1A11Prepared {
        try admission.verifyCurrentNativeScope()
        try admission.verifyR1ProductScope()
        guard flow.owner.store.productNativeQualification,
              let binding = flow.binding else { throw R1A11Fault.scope }
        try admission.verifyLimitedExtraction(binding: binding, attemptID: attemptID,
                                               destinationRoot: destinationRoot)
        return try prepareBoundCurrent(flow: flow, actorID: actorID, sessionID: sessionID)
    }

    private func prepareBoundCurrent(flow: R1ProductFlow, actorID: UUID,
                                     sessionID: UUID) throws -> R1A11Prepared {
        let owner = flow.owner
        guard let session = flow.session, let binding = flow.binding,
              let id = flow.currentJobID, binding.jobID == id else { throw R1A11Fault.scope }
        let decision = session.snapshot(now: flow.currentReviewTime())
        guard decision.decision == R1ReviewDecision.confirmed.rawValue,
              decision.inspectionStatus == "COMPLETE",
              decision.promptInjection == "NOT_DETECTED",
              decision.engineGate == "CAP", decision.unknownCount == 0,
              decision.findingsCount == 0 else { throw R1A11Fault.confirmation }
        guard actorID == binding.ownerID else { throw R1A11Fault.actor }
        guard sessionID == binding.sessionID && sessionID == owner.store.sessionID,
              binding.ownerID == owner.store.registration.ownerID,
              binding.storeID == owner.store.registration.storeID,
              binding.workerJSONStatus == "VALID", binding.workerDirectReap,
              binding.workerPipeFDsClosed, binding.inputFDClosedAfterReturn,
              binding.displayedInputSHA256 == binding.copiedZIPSHA256,
              let receipt = flow.lastReceiptData,
              hash54(receipt) == binding.workerReceiptSHA256 else { throw R1A11Fault.identity }
        guard !consumed.contains(id) else { throw R1A11Fault.attempt }
        consumed.insert(id) // Ambiguous failure has no automatic retry in this process.
        let bytes = try owner.withCurrentWaitingZIP(id) { row, fd, identity -> Data in
            guard row.ownerID == binding.ownerID, row.storeID == binding.storeID,
                  row.jobID == binding.jobID, row.revision == binding.jobRevision,
                  row.sourceKey == binding.sourceKey,
                  row.intakeInputID == binding.intakeInputID,
                  row.intakeAttemptID == binding.intakeAttemptID,
                  row.artifact?.size == binding.copiedZIPSize,
                  row.artifact?.sha256 == binding.copiedZIPSHA256,
                  Int64(identity.device) == binding.copiedZIPDevice,
                  UInt64(identity.inode) == binding.copiedZIPInode,
                  UInt32(identity.uid) == binding.copiedZIPUID else { throw R1A11Fault.identity }
            guard binding.copiedZIPSize > 0 && binding.copiedZIPSize <= 8_388_608 else { throw R1A11Fault.limit }
            var content = Data()
            var chunk = [UInt8](repeating: 0, count: 65_536)
            while content.count < Int(binding.copiedZIPSize) {
                let amount = min(chunk.count, Int(binding.copiedZIPSize) - content.count)
                let got = chunk.withUnsafeMutableBytes { pread(fd, $0.baseAddress, amount, off_t(content.count)) }
                guard got > 0 && got <= amount else { throw R1A11Fault.identity }
                content.append(contentsOf: chunk.prefix(got))
            }
            guard hash54(content) == binding.copiedZIPSHA256 else { throw R1A11Fault.identity }
            return content
        }
        let members = try R1A11StoredZIP.parse(bytes)
        let current = try owner.snapshot(id).job
        guard current.revision == binding.jobRevision, current.state == .waiting,
              current.artifact?.sha256 == binding.copiedZIPSHA256,
              session.snapshot(now: flow.currentReviewTime()).decision == R1ReviewDecision.confirmed.rawValue else {
            throw R1A11Fault.expired
        }
        return R1A11Prepared(binding: binding, actorID: actorID, members: members)
    }
}

enum R1A11PrivateWriter {
    private static func checkDirectory(_ fd: Int32, owner: uid_t) throws {
        var s = stat()
        guard fstat(fd, &s) == 0, s.st_mode & S_IFMT == S_IFDIR,
              s.st_uid == owner, s.st_mode & 0o777 == 0o700 else { throw R1A11Fault.destination }
    }
    private static func readFile(_ fd: Int32, length: Int) throws -> Data {
        var content = Data()
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while content.count < length {
            let amount = min(buffer.count, length - content.count)
            let n = buffer.withUnsafeMutableBytes {
                pread(fd, $0.baseAddress, amount, off_t(content.count))
            }
            guard n > 0 else { throw R1A11Fault.readback }
            content.append(contentsOf: buffer.prefix(n))
        }
        return content
    }
    static func write(_ members: [R1A11Member], to root: URL, jobID: UUID) throws -> URL {
        guard root.isFileURL && root.path.hasPrefix("/"), !root.path.utf8.contains(0) else {
            throw R1A11Fault.destination
        }
        let parent = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard parent >= 0 else { throw R1A11Fault.destination }
        defer { _ = Darwin.close(parent) }
        try checkDirectory(parent, owner: geteuid())
        var pathStat = stat(), fdStat = stat()
        guard lstat(root.path, &pathStat) == 0, fstat(parent, &fdStat) == 0,
              pathStat.st_dev == fdStat.st_dev, pathStat.st_ino == fdStat.st_ino else {
            throw R1A11Fault.destination
        }
        let name = "r1-a11-" + jobID.uuidString.lowercased()
        guard mkdirat(parent, name, 0o700) == 0 else { throw R1A11Fault.destination }
        let folder = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard folder >= 0 else { throw R1A11Fault.destination }
        defer { _ = Darwin.close(folder) }
        try checkDirectory(folder, owner: geteuid())
        var knownDirectories = Set<String>()
        for member in members {
            let parts = member.path.split(separator: "/").map(String.init)
            var current = dup(folder)
            guard current >= 0 else { throw R1A11Fault.write }
            defer { _ = Darwin.close(current) }
            var prefix = ""
            for part in parts.dropLast() {
                prefix += "/" + part.lowercased()
                if !knownDirectories.contains(prefix) {
                    guard mkdirat(current, part, 0o700) == 0 else { throw R1A11Fault.write }
                    knownDirectories.insert(prefix)
                }
                let next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw R1A11Fault.write }
                try checkDirectory(next, owner: geteuid())
                _ = Darwin.close(current); current = next
            }
            guard let leaf = parts.last else { throw R1A11Fault.path }
            let out = openat(current, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard out >= 0 else { throw R1A11Fault.write }
            var written = 0
            do {
                while written < member.content.count {
                    let n = member.content.withUnsafeBytes {
                        Darwin.write(out, $0.baseAddress!.advanced(by: written), member.content.count - written)
                    }
                    guard n > 0 else { throw R1A11Fault.write }
                    written += n
                }
                guard fsync(out) == 0 else { throw R1A11Fault.write }
            } catch { _ = Darwin.close(out); throw error }
            _ = Darwin.close(out)
            let check = openat(current, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard check >= 0 else { throw R1A11Fault.readback }
            var s = stat()
            let valid = fstat(check, &s) == 0 && s.st_mode & S_IFMT == S_IFREG &&
                s.st_uid == geteuid() && s.st_nlink == 1 && s.st_mode & 0o777 == 0o600 &&
                s.st_size == Int64(member.content.count)
            let data = try valid ? readFile(check, length: member.content.count) : Data()
            _ = Darwin.close(check)
            guard valid && hash54(data) == member.sha256 else { throw R1A11Fault.readback }
            guard fsync(current) == 0 else { throw R1A11Fault.write }
        }
        guard fsync(folder) == 0, fsync(parent) == 0 else { throw R1A11Fault.write }
        let url = root.appendingPathComponent(name, isDirectory: true)
        guard lstat(url.path, &pathStat) == 0, fstat(folder, &fdStat) == 0,
              pathStat.st_dev == fdStat.st_dev, pathStat.st_ino == fdStat.st_ino else {
            throw R1A11Fault.readback
        }
        return url
    }
}
