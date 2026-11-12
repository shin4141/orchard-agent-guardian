// Synthetic same-volume extraction only. No cross-volume copy or delete fallback.
import Foundation
import Darwin

enum ExtractionFaultB: String, Error {
    case selection, stale, destinationExists, differentVolume, busy, identity, metadata, io, moveUnknown
}
enum ExtractionPhaseB: String, Codable { case intent, renamedSynced, completed }
struct MetadataSealExtractionB: Codable, Equatable {
    var flags: UInt32
    var xattrsSHA256: String
}
struct ExtractionTransferB: Codable {
    var requestID: UUID
    var jobID: UUID
    var ownerID: UUID
    var storeID: UUID
    var sessionID: UUID
    var requestedRevision: Int
    var sourceArtifactSHA256: String
    var sourceArtifactDigest: String
    var destinationParentPath: String
    var destinationParent: StampJobB
    var destinationLeaf: String
    var metadata: MetadataSealExtractionB
    var phase: ExtractionPhaseB
    var destinationStamp: StampJobB?
    var handlesClosed: Bool
    var holdReason: String?
}
struct SyntheticExtractionSelectionB {
    let requestID: UUID
    let jobID: UUID
    let ownerID: UUID
    let storeID: UUID
    let sessionID: UUID
    let revision: Int
    let artifactDigest: String
    let destinationParentPath: String
    let destinationParent: StampJobB
    let destinationLeaf: String
}
func validExtractionLeafB(_ name: String) -> Bool {
    !name.isEmpty && name.utf8.count <= 80 && name.lowercased().hasSuffix(".zip")
        && name.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0)
            || (97...122).contains($0) || [45,46,95].contains($0) }
        && name != "." && name != ".."
}
func absentExtractionB(_ fd: Int32, _ leaf: String) throws -> Bool {
    var value = stat(); errno = 0
    if fstatat(fd, leaf, &value, AT_SYMLINK_NOFOLLOW) == 0 { return false }
    guard errno == ENOENT else { throw ExtractionFaultB.identity }
    return true
}
func directoryExtractionB(_ url: URL, expected: StampJobB? = nil) throws -> (Int32, StampJobB) {
    let fd = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
    guard fd >= 0 else { throw ExtractionFaultB.identity }
    do {
        var value = stat(), path = stat()
        guard fstat(fd, &value) == 0, lstat(url.path, &path) == 0,
              value.st_uid == geteuid(), value.st_mode & S_IFMT == S_IFDIR,
              value.st_mode & 0o777 == 0o700, StampJobB(value).directory(path),
              expected?.directory(value) ?? true else { throw ExtractionFaultB.identity }
        return (fd, StampJobB(value))
    } catch { _ = Darwin.close(fd); throw error }
}
func selectedDestinationPathB(_ url: URL) throws -> String {
    // standardizing an existing /private/tmp URL can produce the /tmp symlink alias.
    // Preserve the chosen physical spelling; do not resolve aliases or symlinks here.
    guard url.isFileURL, url.host == nil || url.host == "", url.query == nil, url.fragment == nil,
          url.path.hasPrefix("/"), !url.path.utf8.contains(0),
          !url.pathComponents.contains(".."), !url.pathComponents.contains(".") else { throw ExtractionFaultB.selection }
    return url.path
}
func rejectStoreAncestorExtractionB(_ fd: Int32, store: PersistentJobsB) throws {
    var cursor = fcntl(fd, F_DUPFD_CLOEXEC, 0)
    guard cursor >= 0 else { throw ExtractionFaultB.identity }
    defer { _ = closeFD_B(&cursor) }
    for _ in 0..<64 {
        var current = stat(), parentInfo = stat()
        guard fstat(cursor, &current) == 0 else { throw ExtractionFaultB.identity }
        for forbidden in [store.anchor.root, store.anchor.waiting] {
            guard forbidden.dev != Int64(current.st_dev) || forbidden.ino != UInt64(current.st_ino) else { throw ExtractionFaultB.selection }
        }
        var parent = openat(cursor, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parent >= 0, fstat(parent, &parentInfo) == 0 else {
            _ = closeFD_B(&parent); throw ExtractionFaultB.identity
        }
        if current.st_dev == parentInfo.st_dev && current.st_ino == parentInfo.st_ino {
            let a = closeFD_B(&parent), b = closeFD_B(&cursor)
            guard a && b else { throw ExtractionFaultB.io }
            return
        }
        guard closeFD_B(&cursor) else { _ = closeFD_B(&parent); throw ExtractionFaultB.io }
        cursor = parent
    }
    throw ExtractionFaultB.selection
}
func metadataExtractionB(_ fd: Int32) throws -> MetadataSealExtractionB {
    var info = stat(); guard fstat(fd, &info) == 0 else { throw ExtractionFaultB.metadata }
    let raw = try readXattrsProtectionB(fd)
    return MetadataSealExtractionB(flags: info.st_flags, xattrsSHA256: hash54(try canonicalJobB(raw)))
}
func verifyExtractionFileB(url: URL, fd: Int32, artifact: ArtifactJobB,
                           exact: StampJobB? = nil) throws -> (StampJobB, MetadataSealExtractionB) {
    var value = stat(), path = stat()
    guard fstat(fd, &value) == 0, lstat(url.path, &path) == 0,
          artifact.leaf.object(value), StampJobB(value).exact(path),
          value.st_mode & S_IFMT == S_IFREG, [mode_t(0o400), mode_t(0o600)].contains(value.st_mode & 0o7777),
          value.st_uid == geteuid(), value.st_nlink == 1, value.st_size == artifact.size,
          exact?.exact(value) ?? true else { throw ExtractionFaultB.identity }
    try requireMaterializedB(value.st_flags)
    let pin = try PinnedRead54(url: url, size: artifact.size, sha256: artifact.sha256)
    do { try pin.openAndPin(selectedFD: fd, selectedIdentity: FileIdentity54(value)) {} }
    catch { _ = pin.closeOwned(); throw error }
    guard pin.closeOwned() else { throw ExtractionFaultB.io }
    guard let proof = artifact.protection else { throw ExtractionFaultB.metadata }
    try verifyStoredProtectionB(fd, evidence: proof, strictIdentity: false)
    return (StampJobB(value), try metadataExtractionB(fd))
}

final class BoundSyntheticMoveB {
    let store: PersistentJobsB
    let artifact: ArtifactJobB
    let selection: SyntheticExtractionSelectionB
    let sourceURL: URL
    let destinationURL: URL
    private var areaFD: Int32 = -1
    private var destinationFD: Int32 = -1
    private var sourceFD: Int32 = -1
    private(set) var metadata: MetadataSealExtractionB

    init(store: PersistentJobsB, job: RecordJobB, selection: SyntheticExtractionSelectionB) throws {
        guard let artifact = job.artifact else { throw ExtractionFaultB.identity }
        self.store = store; self.artifact = artifact; self.selection = selection
        sourceURL = store.waiting.appendingPathComponent(artifact.areaName).appendingPathComponent("pending.zip")
        destinationURL = URL(fileURLWithPath: selection.destinationParentPath).appendingPathComponent(selection.destinationLeaf)
        metadata = MetadataSealExtractionB(flags: 0, xattrsSHA256: "")
        do {
            areaFD = try directoryExtractionB(sourceURL.deletingLastPathComponent(), expected: artifact.area).0
            destinationFD = try directoryExtractionB(destinationURL.deletingLastPathComponent(), expected: selection.destinationParent).0
            try rejectStoreAncestorExtractionB(destinationFD, store: store)
            sourceFD = openat(areaFD, "pending.zip", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard sourceFD >= 0, selection.destinationParent.dev == artifact.leaf.dev else { throw ExtractionFaultB.differentVolume }
            metadata = try verifyExtractionFileB(url: sourceURL, fd: sourceFD, artifact: artifact, exact: artifact.leaf).1
            try verifyBefore()
        } catch { _ = closeAll(); throw error }
    }
    func verifyDirectories() throws {
        try store.verifyDirectories()
        var area = stat(), areaPath = stat(), target = stat(), targetPath = stat()
        guard fstat(areaFD, &area) == 0, lstat(sourceURL.deletingLastPathComponent().path, &areaPath) == 0,
              fstat(destinationFD, &target) == 0, lstat(selection.destinationParentPath, &targetPath) == 0,
              artifact.area.directory(area), artifact.area.directory(areaPath),
              selection.destinationParent.directory(target), selection.destinationParent.directory(targetPath)
              else { throw ExtractionFaultB.identity }
    }
    func verifyBefore() throws {
        try verifyDirectories()
        guard Set(try FileManager.default.contentsOfDirectory(atPath: sourceURL.deletingLastPathComponent().path)) == ["pending.zip"],
              try absentExtractionB(destinationFD, selection.destinationLeaf) else { throw ExtractionFaultB.destinationExists }
        let seal = try verifyExtractionFileB(url: sourceURL, fd: sourceFD, artifact: artifact, exact: artifact.leaf).1
        guard seal == metadata else { throw ExtractionFaultB.metadata }
    }
    func renameExclusive() throws {
        // Unsupported flags/filesystems fail closed. Never fall back to ordinary rename/copy/unlink.
        guard renameatx_np(areaFD, "pending.zip", destinationFD, selection.destinationLeaf,
                          UInt32(RENAME_EXCL | RENAME_NOFOLLOW_ANY | RENAME_RESOLVE_BENEATH)) == 0 else {
            if errno == EEXIST { throw ExtractionFaultB.destinationExists }
            if errno == EXDEV { throw ExtractionFaultB.differentVolume }
            throw ExtractionFaultB.moveUnknown
        }
    }
    func verifyAfter() throws -> StampJobB {
        try verifyDirectories()
        guard try absentExtractionB(areaFD, "pending.zip"),
              try FileManager.default.contentsOfDirectory(atPath: sourceURL.deletingLastPathComponent().path).isEmpty else { throw ExtractionFaultB.identity }
        let (stamp, seal) = try verifyExtractionFileB(url: destinationURL, fd: sourceFD, artifact: artifact)
        guard seal == metadata, stamp.msec == artifact.leaf.msec, stamp.mnsec == artifact.leaf.mnsec else { throw ExtractionFaultB.metadata }
        return stamp
    }
    func synchronize() throws {
        guard fsync(sourceFD) == 0, fsync(areaFD) == 0, fsync(destinationFD) == 0 else { throw ExtractionFaultB.io }
    }
    func closeAll() -> Bool {
        let closed = [closeFD_B(&sourceFD), closeFD_B(&areaFD), closeFD_B(&destinationFD)]
        return closed.allSatisfy { $0 }
    }
    deinit { _ = closeAll() }
}

enum ExtractionLocationB: String, Encodable { case source, destination }
struct ExtractionObservationB {
    var location: ExtractionLocationB
    var destinationStamp: StampJobB?
}
func observeExtractionB(store: PersistentJobsB, job: RecordJobB) throws -> ExtractionObservationB {
    guard let x = job.extraction, let a = job.artifact else { throw ExtractionFaultB.identity }
    try store.verifyDirectories()
    let areaURL = store.waiting.appendingPathComponent(a.areaName)
    var areaFD: Int32 = -1, destFD: Int32 = -1, leafFD: Int32 = -1
    func closeObservedHandles() -> Bool {
        let closed = [closeFD_B(&leafFD), closeFD_B(&areaFD), closeFD_B(&destFD)]
        return closed.allSatisfy { $0 }
    }
    defer { _ = closeObservedHandles() }
    if job.cleanup == "REMOVED" {
        var v = stat(); errno = 0
        guard lstat(areaURL.path, &v) == -1 && errno == ENOENT else { throw ExtractionFaultB.identity }
    } else { areaFD = try directoryExtractionB(areaURL, expected: a.area).0 }
    destFD = try directoryExtractionB(URL(fileURLWithPath: x.destinationParentPath), expected: x.destinationParent).0
    let sourceAbsent: Bool
    if areaFD < 0 { sourceAbsent = true } else { sourceAbsent = try absentExtractionB(areaFD, "pending.zip") }
    let destAbsent = try absentExtractionB(destFD, x.destinationLeaf)
    if !sourceAbsent && destAbsent {
        leafFD = openat(areaFD, "pending.zip", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard leafFD >= 0, Set(try FileManager.default.contentsOfDirectory(atPath: areaURL.path)) == ["pending.zip"] else { throw ExtractionFaultB.identity }
        let seal = try verifyExtractionFileB(url: areaURL.appendingPathComponent("pending.zip"), fd: leafFD, artifact: a, exact: a.leaf).1
        guard seal == x.metadata else { throw ExtractionFaultB.metadata }
        guard closeObservedHandles() else { throw ExtractionFaultB.io }
        return ExtractionObservationB(location: .source, destinationStamp: nil)
    }
    if sourceAbsent && !destAbsent {
        if areaFD >= 0 { guard try FileManager.default.contentsOfDirectory(atPath: areaURL.path).isEmpty else { throw ExtractionFaultB.identity } }
        let url = URL(fileURLWithPath: x.destinationParentPath).appendingPathComponent(x.destinationLeaf)
        leafFD = openat(destFD, x.destinationLeaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard leafFD >= 0 else { throw ExtractionFaultB.identity }
        let (stamp, seal) = try verifyExtractionFileB(url: url, fd: leafFD, artifact: a, exact: x.destinationStamp)
        guard seal == x.metadata else { throw ExtractionFaultB.metadata }
        guard closeObservedHandles() else { throw ExtractionFaultB.io }
        return ExtractionObservationB(location: .destination, destinationStamp: stamp)
    }
    throw ExtractionFaultB.identity // Both present or both absent is not a successful move.
}
func removeEmptyExtractedAreaB(store: PersistentJobsB, job: RecordJobB) throws {
    guard let a = job.artifact, job.extraction?.phase == .completed else { throw ExtractionFaultB.identity }
    if job.cleanup == "REMOVED" { return }
    let parent = try directoryExtractionB(store.waiting, expected: store.anchor.waiting).0
    let areaURL = store.waiting.appendingPathComponent(a.areaName)
    var area: Int32 = -1
    defer { _ = Darwin.close(parent); _ = closeFD_B(&area) }
    area = try directoryExtractionB(areaURL, expected: a.area).0
    var path = stat()
    guard try FileManager.default.contentsOfDirectory(atPath: areaURL.path).isEmpty,
          fstatat(parent, a.areaName, &path, AT_SYMLINK_NOFOLLOW) == 0, a.area.directory(path) else { throw ExtractionFaultB.identity }
    guard unlinkat(parent, a.areaName, AT_REMOVEDIR) == 0, fsync(parent) == 0,
          try absentExtractionB(parent, a.areaName) else { throw ExtractionFaultB.io }
}
