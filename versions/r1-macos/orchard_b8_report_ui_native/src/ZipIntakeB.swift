// Undeployed ZIP routing and opaque selected-FD staging. No archive reader.
import Foundation
import Darwin

enum ZipFaultB: String, Error {
    case cardinality, nonFileURL, notZipRoute, metadataUnknown, nonRegular, aliasOrPackage
    case cloudOrRemote, dataless, size, sourceChanged, accessEnded, cancelled, duplicate, busy
    case io, ownerChanged, unexpectedMember, copyUnconfirmed, protectionHold
}

struct MetadataB {
    var regular: Bool? = true
    var directory: Bool? = false
    var symbolic: Bool? = false
    var alias: Bool? = false
    var package: Bool? = false
    var ubiquitous: Bool? = false
    var localVolume: Bool? = true

    func qualify() throws {
        guard let regular, let directory, let symbolic, let alias, let package,
              let ubiquitous, let localVolume else { throw ZipFaultB.metadataUnknown }
        guard regular && !directory && !symbolic else { throw ZipFaultB.nonRegular }
        guard !alias && !package else { throw ZipFaultB.aliasOrPackage }
        // No cloud materialization or remote retrieval in this initial profile.
        guard !ubiquitous && localVolume else { throw ZipFaultB.cloudOrRemote }
    }
}

protocol MetadataProbeB {
    func inspect(_ url: URL) throws -> MetadataB
}

func combineCloudFactB(resource: Bool?, queried: Bool) -> Bool? {
    // A missing URL resource value is not false. Use the separate FileManager
    // metadata query; contradictory evidence remains unknown.
    if let resource, resource != queried { return nil }
    return queried
}

struct FoundationMetadataProbeB: MetadataProbeB {
    func inspect(_ url: URL) throws -> MetadataB {
        let v = try url.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey,
            .isSymbolicLinkKey, .isAliasFileKey, .isPackageKey, .isUbiquitousItemKey, .volumeIsLocalKey])
        let cloud = combineCloudFactB(resource: v.isUbiquitousItem,
                                     queried: FileManager.default.isUbiquitousItem(at: url))
        return MetadataB(regular: v.isRegularFile, directory: v.isDirectory,
            symbolic: v.isSymbolicLink, alias: v.isAliasFile, package: v.isPackage,
            ubiquitous: cloud, localVolume: v.volumeIsLocal)
    }
}

protocol AccessLeaseB: AnyObject {
    var active: Bool { get }
    func begin(_ url: URL) -> Bool
    func end()
}

final class SecurityScopedURLLeaseB: AccessLeaseB {
    private var url: URL?
    private(set) var active = false
    func begin(_ url: URL) -> Bool {
        guard self.url == nil, url.startAccessingSecurityScopedResource() else { return false }
        self.url = url; active = true; return true
    }
    func end() {
        if active { url?.stopAccessingSecurityScopedResource() }
        active = false; url = nil
    }
}

final class CancellationB { var requested = false }

func requireMaterializedB(_ flags: UInt32) throws {
    guard flags & UInt32(SF_DATALESS) == 0 else { throw ZipFaultB.dataless }
}

struct WaitingReceiptB: Encodable {
    let inputID: UUID
    let attemptID: UUID
    let size: Int64
    let sha256: String
    let state = "OPAQUE_ZIP_ROUTE_WAITING"
    let evidenceScope = "OFFLINE_SYNTHETIC_BYTES_ONLY"
    let formatValidity = "UNKNOWN_NOT_PARSED"
    let safety = "UNKNOWN_NOT_INSPECTED"
    let authorityIssued = false
    let aConnected = false
}

struct IntakeResultB: Encodable {
    var state: String
    var reason: String
    var recovery: String
    var receipt: WaitingReceiptB?
    var protection: ProtectionEvidenceB? = nil
    let authorityIssued = false
    let aConnected = false
}

func sameDirectoryB(_ expected: FileIdentity54, _ current: stat) -> Bool {
    // Directory membership changes nlink; file identity retains the original strict rule.
    expected.device == current.st_dev && expected.inode == current.st_ino
        && expected.mode == current.st_mode && expected.uid == current.st_uid
        && current.st_mode & S_IFMT == S_IFDIR && current.st_mode & 0o777 == 0o700
}

func closeFD_B(_ fd: inout Int32) -> Bool {
    guard fd >= 0 else { return true }
    let saved = fd; fd = -1
    guard Darwin.close(saved) == 0 else { return false }
    errno = 0
    return fcntl(saved, F_GETFD) == -1 && errno == EBADF
}

final class PendingAreaB {
    let parent: URL
    let attemptID: UUID
    let areaName: String
    let leafName = "pending.zip"
    private var parentFD: Int32 = -1
    private var areaFD: Int32 = -1
    private(set) var outputFD: Int32 = -1
    private var parentIdentity: FileIdentity54?
    private var parentProtection: ProtectionSnapshotB?
    private let parentAudit: (StagingParentObservationB) -> Void
    private var areaIdentity: FileIdentity54?
    private var outputIdentity: FileIdentity54?
    private var outputGID: gid_t?
    private var outputMode: mode_t = 0o600
    private var allocated = false
    private var removed = false

    var areaURL: URL { parent.appendingPathComponent(areaName, isDirectory: true) }
    var outputURL: URL { areaURL.appendingPathComponent(leafName) }

    init(parent: URL, attemptID: UUID, parentAudit: @escaping (StagingParentObservationB) -> Void = { _ in }) throws {
        self.parentAudit = parentAudit
        self.parent = parent; self.attemptID = attemptID; areaName = "zip-b-" + attemptID.uuidString
        parentFD = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard parentFD >= 0 else {
            let code = errno
            parentAudit(StagingParentObservationB(phase: "OPEN", outcome: "HOLD", mismatches: ["parent_open_nofollow"], systemError: code))
            throw ProtectionFailureB(code: "STAGING_PARENT_OPEN_FAILED", item: "parent", systemError: code)
        }
        do {
            // captureProtectionB positively checks directory type, fstat stability and named path equality.
            // UID/0700/flags/ACL are checked before any child allocation; no predicate is skipped.
            parentProtection = try assertStagingParentProtectionB(parentFD, path: parent, audit: parentAudit)
            var value = stat()
            guard fstat(parentFD, &value) == 0, value.st_uid == geteuid(),
                  value.st_mode & S_IFMT == S_IFDIR, value.st_mode & 0o777 == 0o700,
                  parentProtection?.identity == ProtectionStampB(value) else { throw ZipFaultB.ownerChanged }
            parentIdentity = FileIdentity54(value)
        } catch { _ = closeFD_B(&parentFD); throw error }
    }

    func verifyParent() throws {
        var fd = stat(), path = stat()
        guard parentFD >= 0, let expected = parentIdentity, let protection = parentProtection,
              fstat(parentFD, &fd) == 0, lstat(parent.path, &path) == 0,
              sameDirectoryB(expected, fd), sameDirectoryB(expected, path) else {
            let code = errno
            parentAudit(StagingParentObservationB(phase: "FD_NAMED_IDENTITY", outcome: "HOLD",
                mismatches: ["FD_or_named_path_or_inode_or_owner_or_mode"], systemError: code))
            throw ProtectionFailureB(code: "STAGING_PARENT_IDENTITY_CHANGED", item: "parent.FD_named_path", systemError: code)
        }
        try assertStagingParentProtectionB(parentFD, path: parent, expected: protection, audit: parentAudit)
    }

    func allocate() throws {
        try verifyParent()
        guard !allocated else { throw ZipFaultB.duplicate }
        guard mkdirat(parentFD, areaName, 0o700) == 0 else { throw ZipFaultB.io }
        allocated = true
        var value = stat()
        guard fstatat(parentFD, areaName, &value, AT_SYMLINK_NOFOLLOW) == 0 else { throw ZipFaultB.io }
        areaIdentity = FileIdentity54(value)
        areaFD = openat(parentFD, areaName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard areaFD >= 0 else { throw ZipFaultB.io }
        outputFD = openat(areaFD, leafName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard outputFD >= 0, fstat(outputFD, &value) == 0 else { throw ZipFaultB.io }
        outputIdentity = FileIdentity54(value); outputGID = value.st_gid
    }

    func verifyLeaf() throws {
        try verifyParent()
        var dir = stat(), path = stat(), leaf = stat()
        guard areaFD >= 0, let area = areaIdentity, let output = outputIdentity,
              fstat(areaFD, &dir) == 0, fstatat(parentFD, areaName, &path, AT_SYMLINK_NOFOLLOW) == 0,
              sameDirectoryB(area, dir), sameDirectoryB(area, path),
              fstatat(areaFD, leafName, &leaf, AT_SYMLINK_NOFOLLOW) == 0,
              output.sameObject(leaf), leaf.st_mode & S_IFMT == S_IFREG,
              leaf.st_uid == geteuid(), leaf.st_gid == outputGID, leaf.st_mode & 0o7777 == outputMode, leaf.st_nlink == 1 else { throw ZipFaultB.ownerChanged }
        guard Set(try FileManager.default.contentsOfDirectory(atPath: areaURL.path)) == [leafName] else { throw ZipFaultB.unexpectedMember }
    }

    func restrictOutputMode(_ mode: mode_t) throws {
        try verifyLeaf()
        var before = stat(), after = stat()
        guard [mode_t(0o400), mode_t(0o600)].contains(mode), fstat(outputFD, &before) == 0,
              before.st_mode & 0o7777 == 0o600, before.st_size == 0 else { throw ZipFaultB.protectionHold }
        if mode == 0o400 { guard fchmod(outputFD, mode) == 0 else { throw ProtectionFailureB(code: "RESTRICT_MODE_FAILED", item: "staged", systemError: errno) } }
        guard fstat(outputFD, &after) == 0, after.st_dev == before.st_dev, after.st_ino == before.st_ino,
              after.st_uid == before.st_uid, after.st_gid == before.st_gid, after.st_nlink == before.st_nlink,
              after.st_size == 0, after.st_mode & 0o7777 == mode else { throw ZipFaultB.ownerChanged }
        outputIdentity = FileIdentity54(after); outputMode = mode
        try verifyLeaf()
    }
    func protectionSnapshot() throws -> ProtectionSnapshotB {
        try verifyLeaf()
        var fd = openat(areaFD, leafName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ZipFaultB.protectionHold }
        defer { _ = closeFD_B(&fd) }
        let result = try captureProtectionB(fd, path: outputURL)
        guard closeFD_B(&fd) else { throw ZipFaultB.io }
        try verifyLeaf()
        return result
    }

    func finish(size: Int64, sha256: String, checkpoint: @escaping () throws -> Void) throws {
        try checkpoint()
        try verifyLeaf()
        guard fsync(outputFD) == 0, fsync(areaFD) == 0 else { throw ZipFaultB.io }
        guard closeFD_B(&outputFD) else { throw ZipFaultB.io }
        let readback = try PinnedRead54(url: outputURL, size: size, sha256: sha256)
        do {
            try readback.openAndPin()
            try checkpoint()
            try readback.verifyPathAndFD()
        } catch {
            _ = readback.closeOwned(); throw error
        }
        guard readback.closeOwned() else { throw ZipFaultB.io }
        try verifyLeaf()
    }

    func closeStagingHandlesPreservingCopy() throws {
        try verifyLeaf()
        guard closeFD_B(&outputFD), closeFD_B(&areaFD), closeFD_B(&parentFD) else { throw ZipFaultB.io }
    }

    func cleanup() throws -> String {
        guard !removed else { return "ALREADY_ABSENT" }
        guard closeFD_B(&outputFD) else { throw ZipFaultB.io }
        try verifyParent()
        if !allocated {
            removed = true
            guard closeFD_B(&parentFD) else { throw ZipFaultB.io }
            return "NO_AREA_CREATED"
        }
        guard let expected = areaIdentity else { throw ZipFaultB.ownerChanged }
        if areaFD < 0 { areaFD = openat(parentFD, areaName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) }
        var value = stat(), atPath = stat()
        guard areaFD >= 0, fstat(areaFD, &value) == 0,
              fstatat(parentFD, areaName, &atPath, AT_SYMLINK_NOFOLLOW) == 0,
              sameDirectoryB(expected, value), sameDirectoryB(expected, atPath) else { throw ZipFaultB.ownerChanged }
        let expectedNames: Set<String> = outputIdentity == nil ? [] : [leafName]
        guard Set(try FileManager.default.contentsOfDirectory(atPath: areaURL.path)) == expectedNames else { throw ZipFaultB.unexpectedMember }
        if outputIdentity != nil {
            try verifyLeaf()
            guard unlinkat(areaFD, leafName, 0) == 0, fsync(areaFD) == 0 else { throw ZipFaultB.io }
            errno = 0
            guard fstatat(areaFD, leafName, &value, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT else { throw ZipFaultB.io }
        }
        guard fstatat(parentFD, areaName, &value, AT_SYMLINK_NOFOLLOW) == 0,
              sameDirectoryB(expected, value), closeFD_B(&areaFD),
              unlinkat(parentFD, areaName, AT_REMOVEDIR) == 0, fsync(parentFD) == 0 else { throw ZipFaultB.ownerChanged }
        errno = 0
        guard fstatat(parentFD, areaName, &value, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT,
              closeFD_B(&parentFD) else { throw ZipFaultB.io }
        removed = true
        return "OWNED_PENDING_COPY_REMOVED"
    }

    deinit { _ = closeFD_B(&outputFD); _ = closeFD_B(&areaFD); _ = closeFD_B(&parentFD) }
}

final class ZipDropReceiverB {
    static let syntheticCap: Int64 = 256 // Existing synthetic value, never a product ZIP limit.
    static let productOfflineCap: Int64 = 8_388_608
    let pendingParent: URL
    let metadata: MetadataProbeB
    let leaseFactory: () -> AccessLeaseB
    let cancellation: CancellationB
    let maxBytes: Int64
    var checkpoint: (String) throws -> Void = { _ in }
    var protectionOperations = ProtectionOperationsB()
    private var busy = false
    private var consumed = Set<String>()
    private(set) var pending: PendingAreaB?

    init(pendingParent: URL, metadata: MetadataProbeB, leaseFactory: @escaping () -> AccessLeaseB,
         cancellation: CancellationB = CancellationB(), maxBytes: Int64 = ZipDropReceiverB.syntheticCap) {
        self.pendingParent = pendingParent; self.metadata = metadata
        self.leaseFactory = leaseFactory; self.cancellation = cancellation; self.maxBytes = maxBytes
    }

    func receive(_ urls: [URL]) -> IntakeResultB {
        guard maxBytes == Self.syntheticCap || maxBytes == Self.productOfflineCap else { return hold(.size) }
        guard !busy else { return hold(.busy) }
        guard urls.count == 1 else { return hold(.cardinality) }
        let url = urls[0]
        guard url.isFileURL, url.path.hasPrefix("/"), url.host == nil || url.host == "",
              url.query == nil, url.fragment == nil, !url.path.utf8.contains(0),
              !url.pathComponents.contains("..") else { return hold(.nonFileURL) }
        guard url.pathExtension.lowercased() == "zip" else { return hold(.notZipRoute) }
        busy = true; defer { busy = false }
        let lease = leaseFactory()
        guard lease.begin(url) else { return hold(.accessEnded) }
        var sourceFD: Int32 = -1
        var reader: PinnedRead54?
        var area: PendingAreaB?
        var protection: ProtectionSessionB?
        defer { if let reader { _ = reader.closeOwned() }; _ = closeFD_B(&sourceFD); lease.end() }
        func check(_ phase: String) throws {
            try checkpoint(phase)
            guard lease.active else { throw ZipFaultB.accessEnded }
            guard !cancellation.requested else { throw ZipFaultB.cancelled }
            try protection?.recheckSource()
        }
        do {
            try check("received")
            var path = stat()
            guard lstat(url.path, &path) == 0, path.st_mode & S_IFMT == S_IFREG else { throw ZipFaultB.nonRegular }
            try requireMaterializedB(path.st_flags)
            try metadata.inspect(url).qualify()
            try check("metadata_qualified")
            sourceFD = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC)
            var before = stat(), after = stat()
            guard sourceFD >= 0, fstat(sourceFD, &before) == 0,
                  before.st_mode & S_IFMT == S_IFREG, before.st_uid == geteuid(),
                  before.st_nlink == 1 else { throw ZipFaultB.nonRegular }
            try requireMaterializedB(before.st_flags)
            let selected = FileIdentity54(path)
            guard selected.unchanged(before) else { throw ZipFaultB.sourceChanged }
            guard before.st_size > 0, before.st_size <= maxBytes else { throw ZipFaultB.size }
            let key = "\(before.st_dev):\(before.st_ino)"
            guard !consumed.contains(key) else { throw ZipFaultB.duplicate }
            guard pending == nil else { throw ZipFaultB.busy }
            consumed.insert(key) // Failed or cancelled attempts stay consumed for this receiver context.
            try check("selected_fd")
            let context = ProtectionSessionB(fd: sourceFD, path: url, operations: protectionOperations)
            protection = context
            try context.captureSource()
            try check("protection_source_captured")
            var raw = [UInt8](repeating: 0, count: Int(before.st_size + 1))
            let capacity = raw.count
            let count = raw.withUnsafeMutableBytes { pread(sourceFD, $0.baseAddress, capacity, 0) }
            guard count == before.st_size, fstat(sourceFD, &after) == 0,
                  selected.unchanged(after) else { throw ZipFaultB.sourceChanged }
            let sha = hash54(Data(raw.prefix(count))); context.evidence.sourceSHA256 = sha
            let pin = try PinnedRead54(url: url, size: Int64(before.st_size), sha256: sha)
            reader = pin
            try pin.openAndPin(selectedFD: sourceFD, selectedIdentity: selected) { try check("pinned_read") }
            try check("pinned")
            let attemptID = UUID()
            let owned = try PendingAreaB(parent: pendingParent, attemptID: attemptID, parentAudit: context.recordParent)
            area = owned
            try owned.allocate()
            try check("allocated")
            try context.installAttributes(owned.outputFD) { try check($0) }
            guard let privatePermissions = context.evidence.privatePermissions else { throw ZipFaultB.protectionHold }
            try owned.restrictOutputMode(mode_t(privatePermissions.privateMode))
            try context.observeAndMatchOutput(owned.protectionSnapshot(), bytesVerified: false)
            guard fsync(owned.outputFD) == 0 else { throw ZipFaultB.io }
            try check("protection_applied_before_bytes")
            try owned.verifyLeaf()
            try pin.copyTo(owned.outputFD)
            try check("copied")
            try owned.finish(size: Int64(before.st_size), sha256: sha) { try check("copy_readback") }
            context.evidence.bytesVerified = true
            try check("before_waiting")
            try context.observeAndMatchOutput(owned.protectionSnapshot(), bytesVerified: true)
            try context.recheckSource()
            guard context.evidence.acceptedProof, try canonicalJobB(context.evidence).count <= 24000 else { throw ZipFaultB.protectionHold }
            try pin.verifyPathAndFD()
            guard pin.closeOwned(), closeFD_B(&sourceFD) else { throw ZipFaultB.io }
            reader = nil
            pending = owned
            let receipt = WaitingReceiptB(inputID: UUID(), attemptID: attemptID, size: Int64(before.st_size), sha256: sha)
            return IntakeResultB(state: "WAITING", reason: "OPAQUE_BYTES_PINNED_NOT_INSPECTED", recovery: "PENDING_OWNED", receipt: receipt, protection: context.evidence)
        } catch {
            protection?.fail(error)
            if let area, let protection {
                do {
                    let observed = try area.protectionSnapshot()
                    protection.evidence.staged = observed; protection.evidence.stagedObservation = "CAPTURED_AFTER_FAILURE"
                    if let original = protection.evidence.source {
                        protection.evidence.preservedItems = original.values.xattrsBase64.keys.sorted().filter { observed.values.xattrsBase64[$0] == original.values.xattrsBase64[$0] }
                    }
                }
                catch { protection.evidence.stagedObservation = "UNAVAILABLE_AFTER_FAILURE"; protection.evidence.failedItems.append("OUTPUT_OBSERVATION:" + String(describing: error)) }
            }
            if let reader { _ = reader.closeOwned() }
            reader = nil; _ = closeFD_B(&sourceFD)
            var result = hold(error as? ZipFaultB ?? .protectionHold)
            if let area {
                do { result.recovery = try area.cleanup() }
                catch { pending = area; result.recovery = "HOLD_RESOURCE_IDENTITY_OR_RECOVERY" }
            }
            protection?.evidence.recovery = result.recovery
            result.protection = protection?.evidence
            return result
        }
    }

    func releaseStagingHandles() throws {
        guard !busy, let pending else { throw ZipFaultB.busy }
        try pending.closeStagingHandlesPreservingCopy()
        self.pending = nil
    }

    func discardPending() throws -> String {
        guard !busy else { throw ZipFaultB.busy }
        guard let pending else { return "NO_PENDING" }
        let result = try pending.cleanup()
        self.pending = nil
        return result
    }

    private func hold(_ fault: ZipFaultB) -> IntakeResultB {
        IntakeResultB(state: "HOLD", reason: fault.rawValue, recovery: "NO_AREA_CREATED", receipt: nil)
    }
}
