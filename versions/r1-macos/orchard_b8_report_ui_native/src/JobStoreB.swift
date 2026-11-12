// Single-host app-owned prototype store. No authority, worker or window is created here.
import Foundation
import Darwin

enum JobFaultB: String, Error {
    case binding, ownerMismatch, locked, corruptRecord, io, persistenceUnknown
    case duplicate, state, workerIdentity, artifactMismatch, recoveryHold, closed
    case waitingCapacity, retainedCapacity, storageCapacity, inputCapacity, nextConditions, resourceRelease
}

func canonicalJobB<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
}

func decodeJobB<T: Codable>(_ type: T.Type, _ data: Data) throws -> T {
    let result = try JSONDecoder().decode(type, from: data)
    guard try canonicalJobB(result) == data else { throw JobFaultB.corruptRecord }
    return result
}

struct StampJobB: Codable, Equatable {
    var dev: Int64; var ino: UInt64; var mode: UInt32; var uid: UInt32; var links: UInt64
    var size: Int64; var msec: Int64; var mnsec: Int64; var csec: Int64; var cnsec: Int64
    init(_ v: stat) {
        dev = Int64(v.st_dev); ino = UInt64(v.st_ino); mode = UInt32(v.st_mode); uid = v.st_uid
        links = UInt64(v.st_nlink); size = Int64(v.st_size)
        msec = Int64(v.st_mtimespec.tv_sec); mnsec = Int64(v.st_mtimespec.tv_nsec)
        csec = Int64(v.st_ctimespec.tv_sec); cnsec = Int64(v.st_ctimespec.tv_nsec)
    }
    func object(_ v: stat) -> Bool {
        dev == Int64(v.st_dev) && ino == UInt64(v.st_ino) && mode == UInt32(v.st_mode)
            && uid == v.st_uid && links == UInt64(v.st_nlink)
    }
    func directory(_ v: stat) -> Bool {
        dev == Int64(v.st_dev) && ino == UInt64(v.st_ino) && mode == UInt32(v.st_mode)
            && uid == v.st_uid && v.st_mode & S_IFMT == S_IFDIR && v.st_mode & 0o777 == 0o700
    }
    func exact(_ v: stat) -> Bool { self == StampJobB(v) }
}

func statJobB(_ url: URL) throws -> stat {
    var value = stat()
    guard lstat(url.path, &value) == 0 else { throw JobFaultB.artifactMismatch }
    return value
}

func readJobFileB(_ url: URL, cap: Int) throws -> Data {
    let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW_ANY | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { throw JobFaultB.io }; defer { _ = Darwin.close(fd) }
    var before = stat(), after = stat(), path = stat()
    guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
          before.st_uid == geteuid(), before.st_nlink == 1, before.st_mode & 0o777 == 0o600,
          before.st_size >= 0, before.st_size <= cap else { throw JobFaultB.binding }
    var data = Data(); var buffer = [UInt8](repeating: 0, count: min(cap + 1, 65536))
    while data.count < Int(before.st_size) {
        let want = min(buffer.count, Int(before.st_size) - data.count)
        let got = buffer.withUnsafeMutableBytes { pread(fd, $0.baseAddress, want, off_t(data.count)) }
        guard got > 0 else { throw JobFaultB.io }; data.append(contentsOf: buffer.prefix(got))
    }
    guard fstat(fd, &after) == 0, lstat(url.path, &path) == 0,
          StampJobB(before).exact(after), StampJobB(before).exact(path) else { throw JobFaultB.binding }
    return data
}

func exclusiveJobFileB(_ url: URL, _ data: Data) throws {
    let fd = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW_ANY | O_CLOEXEC, 0o600)
    guard fd >= 0 else { throw JobFaultB.io }; defer { _ = Darwin.close(fd) }
    var offset = 0
    while offset < data.count {
        let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
        guard n > 0 else { throw JobFaultB.io }; offset += n
    }
    guard fsync(fd) == 0 else { throw JobFaultB.io }
}

struct QueueLimitsB: Codable, Equatable {
    var retainedJobs = 4
    var waitingJobs = 3
    var retainedBytes: Int64 = 512
    func validate(productQualification: Bool = false) throws {
        guard retainedJobs > 0, retainedJobs <= (productQualification ? 4 : 16),
              waitingJobs > 0, waitingJobs <= retainedJobs,
              retainedBytes >= (productQualification ? 8_388_608 : 256),
              retainedBytes <= (productQualification ? 33_554_432 : 4096) else { throw JobFaultB.binding }
    }
}

enum JobStoreScopeB {
    static let legacySynthetic = "OFFLINE_SYNTHETIC_METADATA_INGRESS_256_NO_A_C"
    static let r1ProductOffline = "R1_PRODUCT_OFFLINE_ZIP_INSPECTION_8M_NO_NATIVE_AUTHORITY"
    static let r1ProductNative = "R1_PRODUCT_NATIVE_8M_REQUIRES_EXACT_AUTHORITY"
}

struct StoreAnchorJobB: Codable {
    var version: Int
    var storeID: UUID
    var ownerID: UUID
    var root: StampJobB
    var waiting: StampJobB
    var lock: StampJobB
    var journal: StampJobB
    var scope: String
    var limits: QueueLimitsB
}

struct RegistrationJobB: Codable {
    var storeID: UUID
    var ownerID: UUID
    var anchorSHA256: String
}

enum StateJobB: String, Codable { case receiving, accepted, waiting, inspecting, finished, interrupted, unknown, extracting, extracted }
enum WorkerScopeJobB: String, Codable { case notConnected, syntheticOnly }

struct ArtifactJobB: Codable {
    var areaName: String
    var area: StampJobB
    var leaf: StampJobB
    var size: Int64
    var sha256: String
    var protection: ProtectionEvidenceB? = nil
}

enum WorkerResourcesB: String, Codable { case none, held, releasePending, released, unknownAfterRestart }

struct RecordJobB: Codable {
    var jobID: UUID
    var ownerID: UUID
    var storeID: UUID
    var sourceKey: String
    var revision: Int
    var queueOrder: Int
    var reservedBytes: Int64
    var workerEnded: Bool
    var resources: WorkerResourcesB
    var recoveryFrom: String?
    var extraction: ExtractionTransferB?
    var intakeProtectionFailure: ProtectionEvidenceB? = nil
    var state: StateJobB
    var reason: String
    var artifact: ArtifactJobB?
    var intakeInputID: UUID?
    var intakeAttemptID: UUID?
    var workerScope: WorkerScopeJobB
    var workerID: UUID?
    var progress: Int
    var target: Int
    var cleanup: String
    var actualInspectionStarted: Bool
    var actualInspectionCompleted: Bool
    var authorityIssued: Bool
    var aConnected: Bool
}

struct PayloadJobB: Codable {
    var seq: Int
    var previous: String
    var ownerID: UUID
    var storeID: UUID
    var sessionID: UUID
    var processID: Int32
    var kind: String
    var job: RecordJobB?
}
struct LineJobB: Codable { var payload: PayloadJobB; var sha256: String }

final class PersistentJobsB {
    let root: URL
    let waiting: URL
    let registration: RegistrationJobB
    let sessionID: UUID
    let anchor: StoreAnchorJobB
    private var rootFD: Int32 = -1
    private var lockFD: Int32 = -1
    private var logFD: Int32 = -1
    private var seq = 0
    private var previous = "ROOT"
    private(set) var healthy = true
    private(set) var isClosed = false
    private(set) var records = [UUID: RecordJobB]()
    var beforeAppend: () throws -> Void = {}
    var productOfflineQualification: Bool { anchor.version == 6 && anchor.scope == JobStoreScopeB.r1ProductOffline }
    var productNativeQualification: Bool { anchor.version == 7 && anchor.scope == JobStoreScopeB.r1ProductNative }
    var productQualification: Bool { productOfflineQualification || productNativeQualification }
    var maxIntakeBytes: Int64 { productQualification ? 8_388_608 : 256 }

    static func create(root: URL, waiting: URL, ownerID: UUID, limits: QueueLimitsB = QueueLimitsB(),
                       productQualification: Bool = false, nativeProductQualification: Bool = false) throws -> RegistrationJobB {
        guard !(productQualification && nativeProductQualification) else { throw JobFaultB.binding }
        let product = productQualification || nativeProductQualification
        try limits.validate(productQualification: product)
        let rootInfo = try statJobB(root), waitingInfo = try statJobB(waiting)
        guard rootInfo.st_uid == geteuid(), waitingInfo.st_uid == geteuid(),
              rootInfo.st_mode & S_IFMT == S_IFDIR, waitingInfo.st_mode & S_IFMT == S_IFDIR,
              rootInfo.st_mode & 0o777 == 0o700, waitingInfo.st_mode & 0o777 == 0o700,
              try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty else { throw JobFaultB.binding }
        let check = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        let waitingCheck = Darwin.open(waiting.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard check >= 0, waitingCheck >= 0 else {
            if check >= 0 { _ = Darwin.close(check) }; if waitingCheck >= 0 { _ = Darwin.close(waitingCheck) }
            throw JobFaultB.binding
        }
        defer { _ = Darwin.close(check); _ = Darwin.close(waitingCheck) }
        try exclusiveJobFileB(root.appendingPathComponent("owner.lock"), Data())
        try exclusiveJobFileB(root.appendingPathComponent("events.jsonl"), Data())
        let anchor = StoreAnchorJobB(version: nativeProductQualification ? 7 : (productQualification ? 6 : 5),
            storeID: UUID(), ownerID: ownerID,
            root: StampJobB(rootInfo), waiting: StampJobB(waitingInfo),
            lock: StampJobB(try statJobB(root.appendingPathComponent("owner.lock"))),
            journal: StampJobB(try statJobB(root.appendingPathComponent("events.jsonl"))),
            scope: nativeProductQualification ? JobStoreScopeB.r1ProductNative :
                (productQualification ? JobStoreScopeB.r1ProductOffline : JobStoreScopeB.legacySynthetic), limits: limits)
        let raw = try canonicalJobB(anchor)
        try exclusiveJobFileB(root.appendingPathComponent("anchor.json"), raw)
        guard fsync(check) == 0 else { throw JobFaultB.io }
        return RegistrationJobB(storeID: anchor.storeID, ownerID: ownerID, anchorSHA256: hash54(raw))
    }

    init(root: URL, waiting: URL, registration: RegistrationJobB,
         sessionID: UUID? = nil) throws {
        self.root = root; self.waiting = waiting; self.registration = registration
        self.sessionID = sessionID ?? UUID()
        let raw = try readJobFileB(root.appendingPathComponent("anchor.json"), cap: 8192)
        guard hash54(raw) == registration.anchorSHA256 else { throw JobFaultB.ownerMismatch }
        anchor = try decodeJobB(StoreAnchorJobB.self, raw)
        let legacy = anchor.version == 5 && anchor.scope == JobStoreScopeB.legacySynthetic
        let productOffline = anchor.version == 6 && anchor.scope == JobStoreScopeB.r1ProductOffline
        let productNative = anchor.version == 7 && anchor.scope == JobStoreScopeB.r1ProductNative
        guard (legacy || productOffline || productNative), anchor.storeID == registration.storeID,
              anchor.ownerID == registration.ownerID else { throw JobFaultB.ownerMismatch }
        try anchor.limits.validate(productQualification: productOffline || productNative)
        do {
            rootFD = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
            guard rootFD >= 0 else { throw JobFaultB.binding }
            try verifyDirectories()
            guard Set(try FileManager.default.contentsOfDirectory(atPath: root.path)) == ["anchor.json", "owner.lock", "events.jsonl"] else { throw JobFaultB.corruptRecord }
            lockFD = openat(rootFD, "owner.lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            var value = stat()
            guard lockFD >= 0, fstat(lockFD, &value) == 0, anchor.lock.object(value) else { throw JobFaultB.ownerMismatch }
            guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { throw JobFaultB.locked }
            logFD = openat(rootFD, "events.jsonl", O_RDWR | O_NOFOLLOW | O_CLOEXEC)
            guard logFD >= 0, fstat(logFD, &value) == 0, anchor.journal.object(value) else { throw JobFaultB.ownerMismatch }
            try load()
            var loadedPath = stat()
            guard fstatat(rootFD, "events.jsonl", &loadedPath, AT_SYMLINK_NOFOLLOW) == 0,
                  anchor.journal.object(loadedPath) else { throw JobFaultB.ownerMismatch }
        } catch {
            _ = closeFD_B(&logFD); _ = closeFD_B(&lockFD); _ = closeFD_B(&rootFD)
            throw error
        }
    }

    func verifyDirectories() throws {
        var fd = stat(), path = stat(), queued = stat()
        guard rootFD >= 0, fstat(rootFD, &fd) == 0, lstat(root.path, &path) == 0,
              lstat(waiting.path, &queued) == 0, anchor.root.directory(fd), anchor.root.directory(path),
              anchor.waiting.directory(queued) else { throw JobFaultB.ownerMismatch }
    }

    private func validate(_ r: RecordJobB) throws {
        guard r.ownerID == registration.ownerID, r.storeID == registration.storeID, r.revision > 0,
              !r.actualInspectionStarted, !r.actualInspectionCompleted, !r.authorityIssued, !r.aConnected,
              !r.sourceKey.isEmpty, r.queueOrder > 0, r.queueOrder <= 1000000,
              r.reservedBytes >= 0, r.reservedBytes <= maxIntakeBytes,
              r.progress >= 0, r.target >= r.progress, r.target <= 10000,
              ["NONE", "REQUESTED", "REMOVED", "HOLD", "EXTRACTED"].contains(r.cleanup) else { throw JobFaultB.corruptRecord }
        if [.accepted, .waiting, .inspecting, .finished, .extracting, .extracted].contains(r.state) && r.artifact == nil { throw JobFaultB.corruptRecord }
        if [.inspecting, .finished].contains(r.state) && (r.workerScope != .syntheticOnly || r.workerID == nil) { throw JobFaultB.corruptRecord }
        if r.workerScope == .notConnected && (r.workerID != nil || r.progress != 0 || r.target != 0) { throw JobFaultB.corruptRecord }
        if r.workerID == nil && ![WorkerResourcesB.none, .released].contains(r.resources) { throw JobFaultB.corruptRecord }
        if r.resources == .released && !r.workerEnded { throw JobFaultB.corruptRecord }
        if let x = r.extraction {
            guard x.jobID == r.jobID, x.ownerID == r.ownerID, x.storeID == r.storeID,
                  x.sourceArtifactSHA256 == r.artifact?.sha256, x.requestedRevision > 0,
                  x.sourceArtifactDigest == hash54(try canonicalJobB(r.artifact)),
                  validExtractionLeafB(x.destinationLeaf), x.destinationParentPath.hasPrefix("/") else { throw JobFaultB.corruptRecord }
            if r.state == .extracted && (x.phase != .completed || !x.handlesClosed || r.reservedBytes != 0) { throw JobFaultB.corruptRecord }
        } else if [.extracting, .extracted].contains(r.state) { throw JobFaultB.corruptRecord }
        if let a = r.artifact {
            guard let protection = a.protection, protection.acceptedProof,
                  protection.source.map({ unsupportedProtectionB($0.values).isEmpty }) == true,
                  protection.sourceSHA256 == a.sha256,
                  protection.staged?.identity.sameAsArtifact(a.leaf) == true,
                  try canonicalJobB(protection).count <= 24000 else { throw JobFaultB.corruptRecord }
            guard a.size > 0, a.size <= maxIntakeBytes, a.sha256.count == 64,
                  a.sha256.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
                  a.areaName.hasPrefix("zip-b-"), UUID(uuidString: String(a.areaName.dropFirst(6))) != nil,
                  a.leaf.size == a.size else { throw JobFaultB.corruptRecord }
        }
    }

    private func validateOrder(_ r: RecordJobB) throws {
        if let previous = records[r.jobID] {
            guard previous.queueOrder == r.queueOrder, previous.sourceKey == r.sourceKey else { throw JobFaultB.corruptRecord }
        } else {
            guard r.queueOrder == (records.values.map(\.queueOrder).max() ?? 0) + 1 else { throw JobFaultB.corruptRecord }
        }
        if let a = r.artifact, r.extraction?.phase != .completed, !["REMOVED", "EXTRACTED"].contains(r.cleanup), r.reservedBytes != a.size { throw JobFaultB.corruptRecord }
        let proposed = records.values.filter { $0.jobID != r.jobID } + [r]
        let retained = proposed.filter { $0.cleanup != "REMOVED" }
        guard retained.count <= anchor.limits.retainedJobs,
              retained.reduce(Int64(0), { $0 + $1.reservedBytes }) <= anchor.limits.retainedBytes,
              proposed.filter({ [.held, .releasePending].contains($0.resources) }).count <= 1 else { throw JobFaultB.corruptRecord }
    }

    private func load() throws {
        let raw = try readJobFileB(root.appendingPathComponent("events.jsonl"), cap: 1_048_576)
        if raw.isEmpty { return }
        guard raw.last == 10 else { throw JobFaultB.corruptRecord }
        for part in raw.split(separator: 10, omittingEmptySubsequences: false).dropLast() {
            guard !part.isEmpty, part.count <= 32768 else { throw JobFaultB.corruptRecord }
            let line = try decodeJobB(LineJobB.self, Data(part)), p = line.payload
            guard p.seq == seq + 1, p.previous == previous, p.ownerID == registration.ownerID,
                  p.storeID == registration.storeID, line.sha256 == hash54(try canonicalJobB(p)) else { throw JobFaultB.corruptRecord }
            if let r = p.job {
                try validate(r)
                guard r.revision == (records[r.jobID]?.revision ?? 0) + 1 else { throw JobFaultB.corruptRecord }
                try validateOrder(r)
                records[r.jobID] = r
            }
            seq = p.seq; previous = line.sha256
        }
    }

    func append(_ kind: String, job: RecordJobB? = nil) throws {
        guard healthy, !isClosed else { throw JobFaultB.persistenceUnknown }
        do {
            try verifyDirectories(); try beforeAppend()
            if let job {
                try validate(job)
                try validateOrder(job)
                guard job.revision == (records[job.jobID]?.revision ?? 0) + 1 else { throw JobFaultB.corruptRecord }
            }
            var value = stat(), atPath = stat()
            guard fstat(logFD, &value) == 0, fstatat(rootFD, "events.jsonl", &atPath, AT_SYMLINK_NOFOLLOW) == 0,
                  anchor.journal.object(value), anchor.journal.object(atPath), value.st_size <= 1_000_000 else { throw JobFaultB.ownerMismatch }
            let payload = PayloadJobB(seq: seq + 1, previous: previous, ownerID: registration.ownerID,
                storeID: registration.storeID, sessionID: sessionID, processID: getpid(), kind: kind, job: job)
            let digest = hash54(try canonicalJobB(payload))
            var raw = try canonicalJobB(LineJobB(payload: payload, sha256: digest)); raw.append(10)
            guard raw.count <= 32768 else { throw JobFaultB.persistenceUnknown }
            let offset = lseek(logFD, 0, SEEK_END)
            guard offset >= 0 else { throw JobFaultB.io }
            var written = 0
            while written < raw.count {
                let n = raw.withUnsafeBytes { Darwin.write(logFD, $0.baseAddress!.advanced(by: written), raw.count - written) }
                guard n > 0 else { throw JobFaultB.io }; written += n
            }
            guard fsync(logFD) == 0, fsync(rootFD) == 0 else { throw JobFaultB.io }
            var back = [UInt8](repeating: 0, count: raw.count)
            let n = back.withUnsafeMutableBytes { pread(logFD, $0.baseAddress, raw.count, offset) }
            guard n == raw.count, Data(back) == raw else { throw JobFaultB.io }
            try verifyDirectories()
            guard fstat(logFD, &value) == 0, fstatat(rootFD, "events.jsonl", &atPath, AT_SYMLINK_NOFOLLOW) == 0,
                  anchor.journal.object(value), anchor.journal.object(atPath),
                  value.st_size == offset + off_t(raw.count) else { throw JobFaultB.ownerMismatch }
            seq = payload.seq; previous = digest
            if let job { records[job.jobID] = job }
        } catch {
            healthy = false; throw error
        }
    }

    func close() {
        if isClosed { return }
        isClosed = true
        _ = closeFD_B(&logFD); _ = closeFD_B(&lockFD); _ = closeFD_B(&rootFD)
    }
    deinit { close() }
}
