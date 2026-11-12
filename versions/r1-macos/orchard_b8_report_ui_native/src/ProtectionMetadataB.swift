// B-only bounded synthetic metadata profile. No source mutations, ACL writes, or safety verdicts.
import Foundation
import Darwin

struct ProtectionFailureB: Error, CustomStringConvertible {
    var code: String
    var item: String
    var systemError: Int32 = 0
    var description: String { "\(code):\(item):errno=\(systemError)" }
}
struct ProtectionStampB: Codable, Equatable {
    var dev: Int64; var ino: UInt64; var mode: UInt32; var uid: UInt32; var gid: UInt32
    var links: UInt64; var size: Int64; var msec: Int64; var mnsec: Int64; var csec: Int64; var cnsec: Int64; var flags: UInt32
    init(_ v: stat) {
        dev = Int64(v.st_dev); ino = UInt64(v.st_ino); mode = UInt32(v.st_mode); uid = v.st_uid; gid = v.st_gid
        links = UInt64(v.st_nlink); size = v.st_size; msec = Int64(v.st_mtimespec.tv_sec); mnsec = Int64(v.st_mtimespec.tv_nsec)
        csec = Int64(v.st_ctimespec.tv_sec); cnsec = Int64(v.st_ctimespec.tv_nsec); flags = v.st_flags
    }
    func sameAsArtifact(_ s: StampJobB) -> Bool {
        dev == s.dev && ino == s.ino && mode == s.mode && uid == s.uid && links == s.links
            && size == s.size && msec == s.msec && mnsec == s.mnsec && csec == s.csec && cnsec == s.cnsec
    }
}
struct ProtectionValuesB: Codable, Equatable {
    var uid: UInt32
    var gid: UInt32
    var permissions: UInt32
    var flags: UInt32
    var aclPresent: Bool
    var aclBinaryBase64: String?
    var xattrsBase64: [String: String]
}
struct ProtectionSnapshotB: Codable, Equatable {
    var identity: ProtectionStampB
    var values: ProtectionValuesB
}
struct SourceAccessClockB: Codable, Equatable {
    var sec: Int64; var nsec: Int64
    init(_ s: stat) { sec = Int64(s.st_atimespec.tv_sec); nsec = Int64(s.st_atimespec.tv_nsec) }
}
func sourceAccessClockB(_ fd: Int32, path: URL, snapshot: ProtectionSnapshotB) throws -> SourceAccessClockB {
    var value = stat(), named = stat()
    guard fstat(fd, &value) == 0, lstat(path.path, &named) == 0,
          ProtectionStampB(value) == snapshot.identity, ProtectionStampB(named) == snapshot.identity,
          SourceAccessClockB(value) == SourceAccessClockB(named) else {
        throw ProtectionFailureB(code: "SOURCE_ACCESS_CLOCK_OR_IDENTITY_UNQUALIFIED", item: "source", systemError: errno)
    }
    return SourceAccessClockB(value)
}
struct PrivatePermissionsB7a: Codable, Equatable {
    var policy = "B7A_OFFLINE_PRIVATE_COPY_CANDIDATE_V1"
    var sourceUID: UInt32; var sourceGID: UInt32; var sourceMode: UInt32
    var privateUID: UInt32; var privateGID: UInt32; var privateMode: UInt32
    var removedModeBits: UInt32; var addedModeBits: UInt32
    var modeDisposition: String
    var groupDisposition: String
    var reason = "APP_OWNED_COPY_NO_GROUP_OR_OTHER_ACCESS_SOURCE_UNCHANGED"
    var impact: String
}
func privateModeB7a(_ source: UInt32) throws -> UInt32 {
    guard source & 0o022 == 0 else {
        throw ProtectionFailureB(code: "SHARED_SOURCE_WRITE_UNSUPPORTED_PINNED_READ_CONTRACT", item: "source-mode")
    }
    guard source & 0o400 != 0, source & 0o7111 == 0 else {
        throw ProtectionFailureB(code: "PRIVATE_COPY_MODE_UNSUPPORTED_HOLD", item: "owner-read-required-no-exec-or-special-bits")
    }
    return source & 0o600 // Restrict the owned copy; never add owner write to a read-only source.
}
func privatePermissionsB7a(_ source: ProtectionValuesB, output: ProtectionValuesB) throws -> PrivatePermissionsB7a {
    let target = try privateModeB7a(source.permissions)
    guard source.uid == geteuid(), output.uid == source.uid, !source.aclPresent, !output.aclPresent,
          source.flags == 0, output.flags == 0 else { throw ProtectionFailureB(code: "PRIVATE_PERMISSION_BINDING_UNSUPPORTED", item: "owner-ACL-flags") }
    return PrivatePermissionsB7a(sourceUID: source.uid, sourceGID: source.gid, sourceMode: source.permissions,
        privateUID: output.uid, privateGID: output.gid, privateMode: target,
        removedModeBits: source.permissions & ~target, addedModeBits: target & ~source.permissions,
        modeDisposition: target == source.permissions ? "MODE_EXACT" : "MODE_RESTRICTED_DOCUMENTED_NOT_EXACT",
        groupDisposition: source.gid == output.gid ? "GID_EXACT" : "NATIVE_PRIVATE_DIRECTORY_GID_RECORDED_NO_GROUP_ACCESS",
        impact: target == source.permissions && source.gid == output.gid
            ? "POSIX_VALUES_EXACT_OTHER_METADATA_SEPARATELY_PROJECTED"
            : "PRIVATE_MODE_PROJECTED_NO_OWNER_ACCESS_ADDED_OTHER_METADATA_SEPARATELY_PROJECTED")
}
// Values remain opaque. The policy is per-name, not a blanket metadata exception.
let supportedAttributeNamesB: Set<String> = ["com.apple.provenance", "com.apple.quarantine",
    "com.apple.metadata:kMDItemWhereFroms", "com.orchard.synthetic.protection", "com.orchard.synthetic.opaque"]
struct MetadataProjectionB: Codable, Equatable {
    var policy = "B8_SOURCE_UNCHANGED_DESTINATION_METADATA_PROJECTION_V3"
    var expectedXattrsBase64: [String: String]
    var decisions: [String: String]
    var sourceValueSHA256: [String: String]
    var initialOutputValueSHA256: [String: String]
}
func attributeDigestsB(_ values: [String: String]) throws -> [String: String] {
    guard values.count <= 8, values.keys.reduce(0, { $0 + $1.utf8.count }) <= 512 else {
        throw ProtectionFailureB(code: "PROJECTION_ATTRIBUTE_LIMIT", item: "names")
    }
    var result = [String: String](), total = 0
    for name in values.keys.sorted() {
        guard supportedAttributeNamesB.contains(name), name.utf8.count <= 128,
              let raw = Data(base64Encoded: values[name]!), raw.base64EncodedString() == values[name]! else {
            throw ProtectionFailureB(code: "PROJECTION_ATTRIBUTE_UNSUPPORTED", item: name)
        }
        total += raw.count
        guard total <= 2048 else { throw ProtectionFailureB(code: "PROJECTION_ATTRIBUTE_LIMIT", item: "values") }
        result[name] = hash54(raw)
    }
    return result
}
func metadataProjectionB(_ source: ProtectionValuesB, initial: ProtectionValuesB) throws -> MetadataProjectionB {
    guard unsupportedProtectionB(source).isEmpty, source.aclBinaryBase64 == nil,
          source.uid == geteuid(), initial.uid == source.uid,
          initial.permissions == 0o600, initial.flags == 0, !initial.aclPresent,
          initial.aclBinaryBase64 == nil else { throw ProtectionFailureB(code: "PROJECTION_OWNER_MODE_ACL_FLAGS", item: "initial") }
    let sourceDigests = try attributeDigestsB(source.xattrsBase64)
    let initialDigests = try attributeDigestsB(initial.xattrsBase64)
    var expected = initial.xattrsBase64, decisions = [String: String]()
    let names = Set(source.xattrsBase64.keys).union(initial.xattrsBase64.keys).union(["com.apple.provenance", "com.apple.quarantine"])
    for name in names.sorted() {
        let origin = source.xattrsBase64[name], existing = initial.xattrsBase64[name]
        if name == "com.apple.provenance" {
            // Per-object OS association. Preserve initial absence OR bytes; never manufacture/copy it.
            decisions[name] = existing == nil ? "DESTINATION_OS_MANAGED_ABSENCE_PRESERVED" : "DESTINATION_OS_MANAGED_VALUE_PRESERVED"
        } else if name == "com.apple.quarantine", existing != nil {
            decisions[name] = "DESTINATION_INITIAL_QUARANTINE_PRESERVED"
        } else if let existing {
            guard existing == origin else { throw ProtectionFailureB(code: "EXISTING_OUTPUT_ATTRIBUTE_MISMATCH_NO_OVERWRITE", item: name) }
            decisions[name] = "EXISTING_EXACT_NO_REWRITE"
        } else if let origin {
            expected[name] = origin
            decisions[name] = "CREATE_SOURCE_ATTRIBUTE_ONLY_IF_ABSENT"
        } else { decisions[name] = "ABSENT_BOTH" }
    }
    return MetadataProjectionB(expectedXattrsBase64: expected, decisions: decisions,
        sourceValueSHA256: sourceDigests, initialOutputValueSHA256: initialDigests)
}
func metadataExceptPrivatePermissionsB7a(_ source: ProtectionValuesB, _ staged: ProtectionValuesB,
    initial: ProtectionValuesB, projection: MetadataProjectionB?) -> Bool {
    guard let projection, let recomputed = try? metadataProjectionB(source, initial: initial), projection == recomputed else { return false }
    return source.uid == staged.uid && source.flags == staged.flags && source.aclPresent == staged.aclPresent
        && source.aclBinaryBase64 == staged.aclBinaryBase64
        && staged.xattrsBase64 == projection.expectedXattrsBase64
}
func validatePrivatePermissionsB7a(_ source: ProtectionValuesB, _ staged: ProtectionValuesB,
    plan: PrivatePermissionsB7a?, initial: ProtectionValuesB, projection: MetadataProjectionB?) -> Bool {
    guard let plan, let recomputed = try? privatePermissionsB7a(source, output: staged) else { return false }
    return plan == recomputed && plan.addedModeBits == 0 && staged.permissions == plan.privateMode
        && staged.permissions & 0o077 == 0
        && metadataExceptPrivatePermissionsB7a(source, staged, initial: initial, projection: projection)
}
func privateCopyObjectB(_ initial: ProtectionStampB, _ current: ProtectionStampB) -> Bool {
    initial.dev == current.dev && initial.ino == current.ino && initial.uid == current.uid && initial.gid == current.gid
        && initial.links == 1 && current.links == 1 && initial.size == 0
        && initial.mode & UInt32(S_IFMT) == UInt32(S_IFREG) && current.mode & UInt32(S_IFMT) == UInt32(S_IFREG)
        && initial.flags == 0 && current.flags == 0
}
func consistentRegularProtectionB(_ s: ProtectionSnapshotB) -> Bool {
    s.identity.mode & UInt32(S_IFMT) == UInt32(S_IFREG) && s.identity.links == 1
        && s.identity.uid == s.values.uid && s.identity.gid == s.values.gid
        && s.identity.mode & 0o7777 == s.values.permissions && s.identity.flags == s.values.flags
}
struct ProtectionEvidenceB: Codable {
    var profile = "B8_OWNER_PRIVATE_COPY_METADATA_PROJECTION_V3"
    var state = "NOT_CAPTURED"
    var source: ProtectionSnapshotB?
    var sourceFinal: ProtectionSnapshotB?
    var sourceFinalDigest: String?
    var stagedObservation = "NOT_CREATED"
    var recovery = "NOT_NEEDED"
    var initialStaged: ProtectionSnapshotB?
    var staged: ProtectionSnapshotB?
    var sourceSHA256: String?
    var sourceStable = false
    var sourceMetadataUnchanged = false
    var sourceAccessClock: SourceAccessClockB?
    var sourceAccessClockFinal: SourceAccessClockB?
    var destinationProjectionVerified = false
    var metadataProjection: MetadataProjectionB?
    var bytesVerified = false
    var metadataVerified = false
    var stagingParentAudit: StagingParentAuditB?
    var privatePermissions: PrivatePermissionsB7a?
    var sourceAndStagedMetadataExact = false
    var preservedItems = [String]()
    var failedItems = [String]()
    var unsupportedItems = [String]()
    var attributeActions = [String: String]()
    var quarantinePolicyEffect = "UNKNOWN_NOT_INTERPRETED_OR_OS_ENFORCEMENT_TESTED"
    var authorityIssued = false
    var safety = "UNKNOWN_NOT_INSPECTED"
    var acceptedProof: Bool {
        guard let source, let staged, let initialStaged, let sourceSHA256, let sourceAccessClock,
              sourceAccessClockFinal == sourceAccessClock,
              let raw = try? canonicalJobB(source), sourceFinalDigest == hash54(raw) else { return false }
        return state == "VERIFIED_BYTES_SOURCE_UNCHANGED_AND_DESTINATION_PROJECTION"
            && bytesVerified && metadataVerified && sourceStable && sourceMetadataUnchanged && destinationProjectionVerified
            && failedItems.isEmpty && unsupportedItems.isEmpty
            && !authorityIssued && safety == "UNKNOWN_NOT_INSPECTED"
            && profile == "B8_OWNER_PRIVATE_COPY_METADATA_PROJECTION_V3"
            && (sourceFinal == nil || sourceFinal == source)
            && consistentRegularProtectionB(source) && consistentRegularProtectionB(initialStaged) && consistentRegularProtectionB(staged)
            && attributeActions == metadataProjection?.decisions
            && sourceSHA256.count == 64 && sourceSHA256.allSatisfy({ $0.isHexDigit && !$0.isUppercase })
            && source.identity.size > 0 && staged.identity.size == source.identity.size
            && (source.identity.dev != staged.identity.dev || source.identity.ino != staged.identity.ino)
            && privateCopyObjectB(initialStaged.identity, staged.identity)
            && sourceAndStagedMetadataExact == (source.values == staged.values)
            && validatePrivatePermissionsB7a(source.values, staged.values, plan: privatePermissions,
                initial: initialStaged.values, projection: metadataProjection)
    }
}

func readXattrsProtectionB(_ fd: Int32) throws -> [String: String] {
    // Refactored from the preceding metadataExtractionB bounded native reader; values stay opaque.
    let count = flistxattr(fd, nil, 0, 0)
    guard count >= 0, count <= 2048 else { throw ProtectionFailureB(code: "ATTRIBUTE_LIST_UNAVAILABLE_OR_LIMIT", item: "xattrs", systemError: errno) }
    var names = [CChar](repeating: 0, count: count)
    if count > 0 {
        let got = names.withUnsafeMutableBytes { flistxattr(fd, $0.baseAddress?.assumingMemoryBound(to: CChar.self), count, 0) }
        guard got == count else { throw ProtectionFailureB(code: "ATTRIBUTE_LIST_CHANGED", item: "xattrs", systemError: errno) }
    }
    let bytes = names.map { UInt8(bitPattern: $0) }
    if count > 0 { guard bytes.last == 0 else { throw ProtectionFailureB(code: "ATTRIBUTE_NAMES_MALFORMED", item: "xattrs") } }
    var list = [String]()
    for part in bytes.split(separator: 0) {
        guard let name = String(bytes: part, encoding: .utf8), !name.isEmpty, name.utf8.count <= 128 else {
            throw ProtectionFailureB(code: "ATTRIBUTE_NAME_UNSUPPORTED", item: "non-UTF8-or-length")
        }
        list.append(name)
    }
    guard list.count <= 8, list.reduce(0, { $0 + $1.utf8.count }) <= 512, Set(list).count == list.count else { throw ProtectionFailureB(code: "ATTRIBUTE_COUNT_LIMIT", item: "xattrs") }
    var result = [String: String](), total = 0
    for name in list.sorted() {
        let size = name.withCString { fgetxattr(fd, $0, nil, 0, 0, 0) }
        guard size >= 0, size <= 2048, total + size <= 2048 else {
            throw ProtectionFailureB(code: "ATTRIBUTE_READ_UNAVAILABLE_OR_LIMIT", item: name, systemError: errno)
        }
        var raw = [UInt8](repeating: 0, count: size)
        let got = name.withCString { name in raw.withUnsafeMutableBytes { fgetxattr(fd, name, $0.baseAddress, size, 0, 0) } }
        guard got == size else { throw ProtectionFailureB(code: "ATTRIBUTE_READ_CHANGED", item: name, systemError: errno) }
        result[name] = Data(raw).base64EncodedString(); total += size
    }
    return result
}

func readACLProtectionB(_ fd: Int32) throws -> (Bool, String?) {
    guard let security = filesec_init() else { throw ProtectionFailureB(code: "ACL_QUERY_UNAVAILABLE", item: "filesec", systemError: errno) }
    defer { filesec_free(security) }
    var info = stat(), present: Int32 = 0
    guard fstatx_np(fd, &info, security) == 0,
          filesec_query_property(security, FILESEC_ACL, &present) == 0 else {
        throw ProtectionFailureB(code: "ACL_QUERY_UNAVAILABLE", item: "FILESEC_ACL", systemError: errno)
    }
    if present == 0 { return (false, nil) } // Explicit property query, not acl_get_fd_np nil/errno inference.
    var acl: acl_t?
    guard filesec_get_property(security, FILESEC_ACL, &acl) == 0, let value = acl,
          UInt(bitPattern: UnsafeRawPointer(value)) > 1 else { throw ProtectionFailureB(code: "ACL_READ_UNAVAILABLE", item: "binary", systemError: errno) }
    defer { _ = acl_free(UnsafeMutableRawPointer(value)) }
    let size = acl_size(value)
    guard size > 0, size <= 1024 else { throw ProtectionFailureB(code: "ACL_BINARY_LIMIT", item: "ACL") }
    var raw = [UInt8](repeating: 0, count: size)
    let got = raw.withUnsafeMutableBytes { acl_copy_ext($0.baseAddress, value, size) }
    guard got == size else { throw ProtectionFailureB(code: "ACL_BINARY_READ_FAILED", item: "ACL", systemError: errno) }
    return (true, Data(raw).base64EncodedString()) // Never resolve names, interpret grants, or copy ACL entries.
}

func captureProtectionB(_ fd: Int32, path: URL? = nil, regular: Bool = true) throws -> ProtectionSnapshotB {
    var before = stat(), after = stat(), currentPath = stat()
    guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == (regular ? S_IFREG : S_IFDIR) else {
        throw ProtectionFailureB(code: "METADATA_FD_INVALID", item: "stat", systemError: errno)
    }
    let attrs = try readXattrsProtectionB(fd), acl = try readACLProtectionB(fd)
    guard fstat(fd, &after) == 0, ProtectionStampB(before) == ProtectionStampB(after) else {
        throw ProtectionFailureB(code: "METADATA_CHANGED_DURING_CAPTURE", item: "identity")
    }
    if let path {
        guard lstat(path.path, &currentPath) == 0, ProtectionStampB(before) == ProtectionStampB(currentPath) else {
            throw ProtectionFailureB(code: "SOURCE_OR_PATH_CHANGED", item: "identity")
        }
    }
    return ProtectionSnapshotB(identity: ProtectionStampB(before), values: ProtectionValuesB(uid: before.st_uid,
        gid: before.st_gid, permissions: UInt32(before.st_mode & 0o7777), flags: before.st_flags,
        aclPresent: acl.0, aclBinaryBase64: acl.1, xattrsBase64: attrs))
}
func unsupportedProtectionB(_ values: ProtectionValuesB) -> [String] {
    // provenance is observed only. Never manufacture/copy its system-managed value.
    let supported = supportedAttributeNamesB
    var items = values.xattrsBase64.keys.filter { !supported.contains($0) }.sorted().map { "XATTR_UNSUPPORTED:" + $0 }
    if values.permissions & 0o022 != 0 { items.append("SHARED_SOURCE_WRITE_UNSUPPORTED_PINNED_READ_CONTRACT") }
    else if (try? privateModeB7a(values.permissions)) == nil { items.append("PRIVATE_COPY_MODE_UNSUPPORTED") }
    if values.uid != geteuid() { items.append("UID_TRANSFORM_UNSUPPORTED") }
    if values.flags != 0 { items.append("BSD_FLAGS_COPY_UNSUPPORTED") }
    if values.aclPresent { items.append("EXTENDED_ACL_COPY_UNSUPPORTED_BINARY_RETAINED") }
    return items
}
// Parent values are observed, never transformed or propagated to the ZIP copy.
struct StagingParentObservationB: Codable, Equatable {
    var phase: String
    var outcome: String
    var mismatches: [String]
    var systemError: Int32
    var identity: ProtectionStampB?
    var uid: UInt32?
    var permissions: UInt32?
    var flags: UInt32?
    var aclPresent: Bool?
    var allowedNames = ["com.apple.provenance", "com.apple.quarantine"]
    var observedValueSHA256 = [String: String]()
}
struct StagingParentAuditB: Codable {
    var first: StagingParentObservationB
    var last: StagingParentObservationB
    var firstFailure: StagingParentObservationB?
    var checks = 1
    mutating func record(_ value: StagingParentObservationB) {
        last = value; checks = min(checks + 1, 1024)
        if firstFailure == nil && value.outcome != "PASS" { firstFailure = value }
    }
}
func parentObservationB(_ s: ProtectionSnapshotB, expected: ProtectionSnapshotB?) -> StagingParentObservationB {
    let v = s.values
    var row = StagingParentObservationB(phase: expected == nil ? "INITIAL" : "RECHECK", outcome: "PASS",
        mismatches: [], systemError: 0, identity: s.identity, uid: v.uid,
        permissions: v.permissions, flags: v.flags, aclPresent: v.aclPresent)
    if s.identity.mode & UInt32(S_IFMT) != UInt32(S_IFDIR) { row.mismatches.append("type") }
    if v.uid != geteuid() { row.mismatches.append("uid") }
    if v.permissions != 0o700 { row.mismatches.append("permissions0700") }
    if v.flags != 0 { row.mismatches.append("BSD_flags") }
    if v.aclPresent || v.aclBinaryBase64 != nil { row.mismatches.append("ACL") }
    for name in v.xattrsBase64.keys.sorted() {
        if !row.allowedNames.contains(name) { row.mismatches.append("unknown_attribute:" + name) }
        if let raw = Data(base64Encoded: v.xattrsBase64[name]!) { row.observedValueSHA256[name] = hash54(raw) }
        else { row.mismatches.append("invalid_attribute_encoding:" + name) }
    }
    if let expected {
        if s.identity.dev != expected.identity.dev || s.identity.ino != expected.identity.ino {
            row.mismatches.append("FD_inode")
        }
        if s.identity.mode != expected.identity.mode { row.mismatches.append("mode_changed") }
        if v.uid != expected.values.uid { row.mismatches.append("uid_changed") }
        if v.gid != expected.values.gid { row.mismatches.append("gid_changed") }
        if v.xattrsBase64 != expected.values.xattrsBase64 { row.mismatches.append("attribute_names_or_values_changed") }
    }
    if !row.mismatches.isEmpty { row.outcome = "HOLD" }
    return row
}
@discardableResult
func assertStagingParentProtectionB(_ fd: Int32, path: URL,
    expected: ProtectionSnapshotB? = nil, audit: (StagingParentObservationB) -> Void = { _ in }) throws -> ProtectionSnapshotB {
    let captured: ProtectionSnapshotB
    do { captured = try captureProtectionB(fd, path: path, regular: false) }
    catch {
        let failure = error as? ProtectionFailureB
        audit(StagingParentObservationB(phase: "CAPTURE", outcome: "HOLD",
            mismatches: [failure?.description ?? String(describing: error)],
            systemError: failure?.systemError ?? 0))
        throw error
    }
    let row = parentObservationB(captured, expected: expected)
    audit(row)
    guard row.outcome == "PASS" else {
        throw ProtectionFailureB(code: "STAGING_PARENT_METADATA_UNSUPPORTED_OR_CHANGED",
            item: "parent." + row.mismatches.joined(separator: ","))
    }
    return captured
}
func createXattrProtectionB(_ fd: Int32, name: String, data: Data) throws {
    let result = name.withCString { name in data.withUnsafeBytes { fsetxattr(fd, name, $0.baseAddress, data.count, 0, XATTR_CREATE) } }
    guard result == 0 else { throw ProtectionFailureB(code: "ATTRIBUTE_CREATE_FAILED", item: name, systemError: errno) }
}
struct ProtectionOperationsB {
    var setAttribute: (Int32, String, Data) throws -> Void = createXattrProtectionB
    var beforeCapture: (Int32) throws -> Void = { _ in }
}
final class ProtectionSessionB {
    let fd: Int32
    let path: URL
    let operations: ProtectionOperationsB
    var evidence = ProtectionEvidenceB()
    init(fd: Int32, path: URL, operations: ProtectionOperationsB) { self.fd = fd; self.path = path; self.operations = operations }
    func recordParent(_ row: StagingParentObservationB) {
        if evidence.stagingParentAudit != nil { evidence.stagingParentAudit!.record(row) }
        else { evidence.stagingParentAudit = StagingParentAuditB(first: row, last: row,
            firstFailure: row.outcome == "PASS" ? nil : row) }
    }
    func captureSource() throws {
        try operations.beforeCapture(fd)
        let source = try captureProtectionB(fd, path: path)
        evidence.sourceAccessClock = try sourceAccessClockB(fd, path: path, snapshot: source)
        evidence.source = source; evidence.sourceFinalDigest = hash54(try canonicalJobB(source)); evidence.state = "SOURCE_CAPTURED_NOT_COPIED"
        evidence.unsupportedItems = unsupportedProtectionB(source.values)
        guard evidence.unsupportedItems.isEmpty else { throw ProtectionFailureB(code: "UNSUPPORTED_SOURCE_METADATA_HOLD", item: evidence.unsupportedItems.joined(separator: ",")) }
        evidence.sourceStable = true; evidence.sourceMetadataUnchanged = true
    }
    func recheckSource() throws {
        guard let original = evidence.source else { return }
        try operations.beforeCapture(fd)
        let current: ProtectionSnapshotB
        do { current = try captureProtectionB(fd, path: path) }
        catch { evidence.sourceStable = false; evidence.sourceMetadataUnchanged = false; throw error }
        evidence.sourceFinalDigest = hash54(try canonicalJobB(current))
        let clock = try sourceAccessClockB(fd, path: path, snapshot: current)
        evidence.sourceAccessClockFinal = clock
        guard evidence.sourceAccessClock == clock else {
            evidence.sourceStable = false; evidence.sourceMetadataUnchanged = false
            throw ProtectionFailureB(code: "SOURCE_ACCESS_CLOCK_CHANGED_HOLD", item: "atime")
        }
        guard current == original else {
            evidence.sourceFinal = current
            evidence.sourceStable = false; evidence.sourceMetadataUnchanged = false
            throw ProtectionFailureB(code: "SOURCE_PROTECTION_CHANGED_HOLD", item: "identity-or-metadata")
        }
        evidence.sourceStable = true; evidence.sourceMetadataUnchanged = true
    }
    func installAttributes(_ outputFD: Int32, checkpoint: (String) throws -> Void) throws {
        guard let source = evidence.source else { throw ProtectionFailureB(code: "SOURCE_NOT_CAPTURED", item: "metadata") }
        let initial = try captureProtectionB(outputFD); evidence.initialStaged = initial
        guard initial.identity.links == 1, initial.identity.size == 0,
              source.identity.dev != initial.identity.dev || source.identity.ino != initial.identity.ino else {
            throw ProtectionFailureB(code: "NEW_OUTPUT_NOT_FRESH_DISTINCT_REGULAR_FILE", item: "staged")
        }
        evidence.privatePermissions = try privatePermissionsB7a(source.values, output: initial.values)
        let projection = try metadataProjectionB(source.values, initial: initial.values)
        evidence.metadataProjection = projection
        evidence.attributeActions = projection.decisions
        let names = projection.expectedXattrsBase64.keys.sorted { a, b in
            if a == "com.apple.quarantine" { return b != a }
            if b == "com.apple.quarantine" { return false }
            return a < b
        }
        for name in names {
            try checkpoint("protection_before_attribute:" + name)
            if initial.values.xattrsBase64[name] == nil {
                guard name != "com.apple.provenance", let encoded = projection.expectedXattrsBase64[name],
                      let raw = Data(base64Encoded: encoded) else { throw ProtectionFailureB(code: "PROJECTION_CREATE_UNQUALIFIED", item: name) }
                // XATTR_CREATE only: a concurrent attribute appearance is HOLD, never overwrite.
                try operations.setAttribute(outputFD, name, raw)
            }
            try checkpoint("protection_after_attribute:" + name)
        }
    }
    func observeAndMatchOutput(_ value: ProtectionSnapshotB, bytesVerified: Bool) throws {
        evidence.staged = value; evidence.stagedObservation = "CAPTURED"; evidence.bytesVerified = bytesVerified
        guard let source = evidence.source, let initial = evidence.initialStaged else { throw ProtectionFailureB(code: "SOURCE_NOT_CAPTURED", item: "metadata") }
        evidence.preservedItems = source.values.xattrsBase64.keys.sorted().filter { value.values.xattrsBase64[$0] == source.values.xattrsBase64[$0] }
        evidence.sourceAndStagedMetadataExact = value.values == source.values
        guard privateCopyObjectB(initial.identity, value.identity),
              validatePrivatePermissionsB7a(source.values, value.values, plan: evidence.privatePermissions,
                initial: initial.values, projection: evidence.metadataProjection) else {
            evidence.metadataVerified = false; evidence.destinationProjectionVerified = false
            throw ProtectionFailureB(code: "STAGED_PROTECTION_MISMATCH_HOLD", item: "permissions-ACL-flags-xattrs")
        }
        evidence.metadataVerified = true; evidence.destinationProjectionVerified = true; evidence.bytesVerified = bytesVerified
        evidence.preservedItems += ["UID_EXACT", "PRIVATE_PERMISSIONS_DOCUMENTED_NO_ADDED_BITS", "NO_BSD_FLAGS_CONFIRMED", "NO_EXTENDED_ACL_CONFIRMED"]
        evidence.state = bytesVerified ? "VERIFIED_BYTES_SOURCE_UNCHANGED_AND_DESTINATION_PROJECTION" : "DESTINATION_PROJECTION_APPLIED_BEFORE_BYTES_NOT_ACCEPTED"
    }
    func fail(_ error: Error) {
        evidence.sourceStable = false // Final intake qualification is unconfirmed after any abort; raw observations remain.
        evidence.metadataVerified = false; evidence.destinationProjectionVerified = false; evidence.sourceMetadataUnchanged = false
        evidence.failedItems.append(String(describing: error))
        if let failure = error as? ProtectionFailureB, failure.code.contains("LIMIT") {
            evidence.unsupportedItems.append(failure.code + ":" + failure.item)
        }
        evidence.state = evidence.unsupportedItems.isEmpty ? "HOLD_NOT_ACCEPTED" : "HOLD_UNSUPPORTED_NOT_ACCEPTED"
    }
}

func verifyStoredProtectionB(_ fd: Int32, evidence: ProtectionEvidenceB, strictIdentity: Bool) throws {
    guard evidence.acceptedProof, let staged = evidence.staged else { throw ProtectionFailureB(code: "PROTECTION_RECEIPT_UNQUALIFIED", item: "artifact") }
    let current = try captureProtectionB(fd)
    guard current.values == staged.values, !strictIdentity || current.identity == staged.identity else {
        throw ProtectionFailureB(code: "PRESENT_PROTECTION_CHANGED", item: "artifact")
    }
}
