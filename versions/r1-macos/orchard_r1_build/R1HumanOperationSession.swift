// Human-started operation composition. This file never launches an app and
// never reads an AI permission/GO file. It checks the running signed product,
// creates only this build's fresh private session and connects existing paths.
import AppKit
import Foundation
import Security
import Darwin

enum R1HumanSessionFault: String, Error {
    case signature, source, container, ownership, consumed, evidence, stopped, resources, input
}

private func r1BoundedOwnedBytes(_ url: URL, cap: Int) throws -> Data {
    let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC)
    guard fd >= 0 else { throw R1HumanSessionFault.ownership }
    defer { _ = Darwin.close(fd) }
    var before = stat(), after = stat(), named = stat()
    guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
          before.st_nlink == 1, before.st_uid == geteuid(), before.st_size > 0,
          before.st_size <= cap else { throw R1HumanSessionFault.ownership }
    var raw = Data(), chunk = [UInt8](repeating: 0, count: 65_536)
    while raw.count < Int(before.st_size) {
        let wanted = min(chunk.count, Int(before.st_size) - raw.count)
        let read = chunk.withUnsafeMutableBytes { pread(fd, $0.baseAddress, wanted, off_t(raw.count)) }
        guard read > 0 else { throw R1HumanSessionFault.ownership }
        raw.append(contentsOf: chunk.prefix(read))
    }
    let identity = FileIdentity54(before)
    guard fstat(fd, &after) == 0, lstat(url.path, &named) == 0,
          identity.unchanged(after), identity.unchanged(named) else { throw R1HumanSessionFault.ownership }
    return raw
}

// UID checks below establish filesystem ownership only, never an A/B/C lane
// principal or Host isolation. Prelaunch source/CDHashes remain B/C evidence.
struct R1HumanCodeObservation: Equatable {
    let bundleURL: URL, home: URL
    let bundleIdentifier: String, productSHA256: String, productCDHash: String
    let workerSHA256: String, workerCDHash: String, workerBytes: Int64, sourceBindingSHA256: String

    private static func signingInfo(_ code: SecStaticCode, keys: Set<String>) throws -> [String: Any] {
        var raw: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &raw) == errSecSuccess,
              let info = raw as? [String: Any],
              let flags = info[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & SecCodeSignatureFlags.adhoc.rawValue != 0,
              (info[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? []).isEmpty,
              let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              Set(entitlements.keys) == keys else { throw R1HumanSessionFault.signature }
        for key in keys {
            guard let value = entitlements[key] as? NSNumber,
                  CFGetTypeID(value) == CFBooleanGetTypeID(), value.boolValue else {
                throw R1HumanSessionFault.signature
            }
        }
        return info
    }

    private static func cdhash(_ info: [String: Any]) throws -> String {
        guard let value = info[kSecCodeInfoUnique as String] as? Data, !value.isEmpty else {
            throw R1HumanSessionFault.signature
        }
        return value.map { String(format: "%02x", $0) }.joined()
    }

    static func capture(in bundle: Bundle = .main) throws -> R1HumanCodeObservation {
        let app = bundle.bundleURL
        guard app == Bundle.main.bundleURL, app.path == app.resolvingSymlinksInPath().path,
              let identifier = bundle.bundleIdentifier, identifier.hasPrefix("com.orchard.release1.a"),
              identifier.count == "com.orchard.release1.a".count + 32,
              R1AppSourceBinding.hex(String(identifier.suffix(32)), 32) else { throw R1HumanSessionFault.source }
        let product = app.appendingPathComponent("Contents/MacOS/OrchardProduct")
        let worker = app.appendingPathComponent("Contents/MacOS/OrchardZipWorker")
        let engine = app.appendingPathComponent("Contents/Resources/OrchardZipWorker/engine/zip_inspector.py")
        let source = app.appendingPathComponent("Contents/Resources/OrchardProduct/SourceBinding.json")
        let productRaw = try r1BoundedOwnedBytes(product, cap: 67_108_864)
        let workerRaw = try r1BoundedOwnedBytes(worker, cap: 67_108_864)
        guard hash54(try r1BoundedOwnedBytes(engine, cap: 18_036)) == R1WorkerRuntime.a1EngineSHA256,
              hash54(workerRaw) != R1WorkerRuntime.a8WorkerSHA256 else { throw R1HumanSessionFault.source }
        let parentKeys: Set<String> = ["com.apple.security.app-sandbox", "com.apple.security.files.user-selected.read-only"]
        let childKeys: Set<String> = ["com.apple.security.app-sandbox", "com.apple.security.inherit"]
        let liveFlags: SecCSFlags = [SecCSFlags(rawValue: kSecCSStrictValidate), .noNetworkAccess]
        let diskFlags: SecCSFlags = [SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures), .noNetworkAccess]
        var live: SecCode?, liveStatic: SecStaticCode?, disk: SecStaticCode?, child: SecStaticCode?
        guard SecCodeCopySelf(SecCSFlags(), &live) == errSecSuccess, let live,
              SecCodeCheckValidity(live, liveFlags, nil) == errSecSuccess,
              SecCodeCopyStaticCode(live, SecCSFlags(), &liveStatic) == errSecSuccess, let liveStatic,
              SecStaticCodeCreateWithPath(app as CFURL, SecCSFlags(), &disk) == errSecSuccess, let disk,
              SecStaticCodeCheckValidity(disk, diskFlags, nil) == errSecSuccess,
              SecStaticCodeCreateWithPath(worker as CFURL, SecCSFlags(), &child) == errSecSuccess, let child,
              SecStaticCodeCheckValidity(child, liveFlags, nil) == errSecSuccess else {
            throw R1HumanSessionFault.signature
        }
        let liveInfo = try signingInfo(liveStatic, keys: parentKeys)
        let diskInfo = try signingInfo(disk, keys: parentKeys)
        let childInfo = try signingInfo(child, keys: childKeys)
        let liveHash = try cdhash(liveInfo), diskHash = try cdhash(diskInfo)
        guard liveHash == diskHash,
              liveInfo[kSecCodeInfoIdentifier as String] as? String == identifier,
              diskInfo[kSecCodeInfoIdentifier as String] as? String == identifier,
              let task = SecTaskCreateFromSelf(nil) else { throw R1HumanSessionFault.signature }
        for key in parentKeys {
            var error: Unmanaged<CFError>?
            guard let effective = SecTaskCopyValueForEntitlement(task, key as CFString, &error), error == nil,
                  CFGetTypeID(effective) == CFBooleanGetTypeID(),
                  (effective as? NSNumber)?.boolValue == true else { throw R1HumanSessionFault.signature }
        }
        guard let user = getpwuid(getuid()), let userHome = user.pointee.pw_dir else {
            throw R1HumanSessionFault.container
        }
        let expectedHome = URL(fileURLWithPath: String(cString: userHome), isDirectory: true)
            .appendingPathComponent("Library/Containers/" + identifier + "/Data", isDirectory: true)
        let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
        var homeStat = stat()
        guard home.path == expectedHome.path, home.path == home.resolvingSymlinksInPath().path,
              lstat(home.path, &homeStat) == 0, homeStat.st_mode & S_IFMT == S_IFDIR,
              homeStat.st_uid == geteuid(), !app.path.hasPrefix(home.path + "/") else {
            throw R1HumanSessionFault.container
        }
        let sourceRaw = try readJobFileB(source, cap: 65_536)
        return R1HumanCodeObservation(bundleURL: app, home: home, bundleIdentifier: identifier,
            productSHA256: hash54(productRaw), productCDHash: diskHash,
            workerSHA256: hash54(workerRaw), workerCDHash: try cdhash(childInfo),
            workerBytes: Int64(workerRaw.count), sourceBindingSHA256: hash54(sourceRaw))
    }

    func verifyCurrent() throws {
        guard try Self.capture() == self else { throw R1HumanSessionFault.signature }
    }

    var json: [String: Any] {
        ["bundle_path": bundleURL.path, "bundle_identifier": bundleIdentifier, "home": home.path,
         "product_sha256": productSHA256, "product_cdhash": productCDHash,
         "worker_sha256": workerSHA256, "worker_cdhash": workerCDHash, "worker_bytes": workerBytes,
         "source_binding_sha256": sourceBindingSHA256, "signature": "adhoc",
         "effective_parent_entitlements": true, "effective_file_network_denials_proven": false,
         "UID_is_lane_principal": false, "native_GO_issued": false]
    }
}

// Exclusive, fsynced event files keep the last durable prefix after an abrupt
// stop. They are observations, never authorization or restart instructions.
final class R1HumanOperationLedger {
    let directory: URL
    private let identity: StampJobB
    private let context: [String: Any]
    private let lock = NSLock()
    private var sequence = 0, failed = false, sealed = false
    private var previous = String(repeating: "0", count: 64)
    init(directory: URL, context: [String: Any]) throws {
        self.directory = directory; self.context = context
        identity = StampJobB(try statJobB(directory))
    }
    var healthy: Bool { lock.lock(); defer { lock.unlock() }; return !failed }
    func record(_ stage: String, _ details: [String: Any]) throws {
        lock.lock(); defer { lock.unlock() }
        guard !failed, !sealed, sequence < 4096 else { throw R1HumanSessionFault.evidence }
        do {
            let fd = try R1A12IO.openRoot(directory)
            defer { _ = Darwin.close(fd) }
            var actual = stat()
            guard fstat(fd, &actual) == 0, identity.directory(actual),
                  identity.directory(try statJobB(directory)) else { throw R1HumanSessionFault.ownership }
            let row: [String: Any] = ["schema": "orchard-r1-human-session-event/1", "sequence": sequence + 1,
                "previous_sha256": previous, "stage": stage, "context": context, "details": details,
                "time_unix": Date().timeIntervalSince1970, "authorizes_actions": false]
            let raw = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys])
            guard raw.count <= 8_388_608 else { throw R1HumanSessionFault.evidence }
            let name = String(format: "event-%06d.json", sequence + 1)
            try R1A12IO.put(fd, name, raw)
            guard try R1A12IO.get(fd, name, cap: 8_388_608) == raw else { throw R1HumanSessionFault.evidence }
            sequence += 1; previous = hash54(raw)
        } catch { failed = true; throw error }
    }

    func sealAndVerifyPrefix() throws {
        lock.lock(); defer { lock.unlock() }
        guard !failed, !sealed else { throw R1HumanSessionFault.evidence }
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted()
        guard sequence > 0 else { throw R1HumanSessionFault.evidence }
        let expected = (1...sequence).map { String(format: "event-%06d.json", $0) }
        guard names == expected else { throw R1HumanSessionFault.evidence }
        let contextRaw = try JSONSerialization.data(withJSONObject: context, options: [.sortedKeys])
        var prefix = String(repeating: "0", count: 64)
        for (index, name) in names.enumerated() {
            let raw = try readJobFileB(directory.appendingPathComponent(name), cap: 8_388_608)
            guard let row = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
                  row["schema"] as? String == "orchard-r1-human-session-event/1",
                  row["sequence"] as? Int == index + 1, row["previous_sha256"] as? String == prefix,
                  row["authorizes_actions"] as? Bool == false, let saved = row["context"] as? [String: Any],
                  try JSONSerialization.data(withJSONObject: saved, options: [.sortedKeys]) == contextRaw else {
                throw R1HumanSessionFault.evidence
            }
            prefix = hash54(raw)
        }
        guard prefix == previous else { throw R1HumanSessionFault.evidence }
        sealed = true
    }
}

struct R1HumanOwnedFile {
    let url: URL, identity: StampJobB, sha256: String, bytes: Int
    init(url: URL, expected: Data) throws {
        self.url = url; identity = StampJobB(try statJobB(url))
        sha256 = hash54(expected); bytes = expected.count
        try verify()
    }
    func verify() throws {
        guard identity.exact(try statJobB(url)),
              hash54(try readJobFileB(url, cap: 4096)) == sha256 else { throw R1HumanSessionFault.ownership }
    }
}

struct R1HumanProcessStamp: Codable, Equatable {
    let pid: Int32, uid: UInt32, startSec: UInt64, startUsec: UInt64
    static func current() throws -> R1HumanProcessStamp {
        var value = proc_bsdinfo()
        guard proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &value, Int32(MemoryLayout<proc_bsdinfo>.size))
                == Int32(MemoryLayout<proc_bsdinfo>.size), value.pbi_pid == getpid() else {
            throw R1HumanSessionFault.ownership
        }
        return R1HumanProcessStamp(pid: getpid(), uid: geteuid(), startSec: UInt64(value.pbi_start_tvsec),
                                   startUsec: UInt64(value.pbi_start_tvusec))
    }
}

final class R1HumanSessionResources {
    let root: URL, store: URL, waiting: URL, extraction: URL, evidence: URL
    let sessionID: UUID, ownerID: UUID
    let process: R1HumanProcessStamp
    let code: R1HumanCodeObservation
    let source: R1ProductExecutionSource
    let ledger: R1HumanOperationLedger
    private let directories: [String: StampJobB]
    private let leaseIdentity: StampJobB
    private let leaseSHA256: String

    private init(root: URL, sessionID: UUID, ownerID: UUID, process: R1HumanProcessStamp,
                 code: R1HumanCodeObservation, source: R1ProductExecutionSource,
                 directories: [String: StampJobB], ledger: R1HumanOperationLedger,
                 leaseIdentity: StampJobB, leaseSHA256: String) {
        self.root = root; self.sessionID = sessionID; self.ownerID = ownerID; self.process = process
        self.code = code; self.source = source; self.directories = directories; self.ledger = ledger
        self.leaseIdentity = leaseIdentity; self.leaseSHA256 = leaseSHA256
        store = root.appendingPathComponent("store", isDirectory: true)
        waiting = root.appendingPathComponent("waiting", isDirectory: true)
        extraction = root.appendingPathComponent("extraction", isDirectory: true)
        evidence = root.appendingPathComponent("evidence", isDirectory: true)
    }

    static func allocate(code: R1HumanCodeObservation, source: R1ProductExecutionSource,
                         ownerID: UUID) throws -> R1HumanSessionResources {
        try code.verifyCurrent()
        let process = try R1HumanProcessStamp.current()
        let homeFD = Darwin.open(code.home.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard homeFD >= 0 else { throw R1HumanSessionFault.container }
        defer { _ = Darwin.close(homeFD) }
        let name = "Orchard-session-" + source.sessionID.uuidString.lowercased()
        let root = code.home.appendingPathComponent(name, isDirectory: true)
        let context: [String: Any] = ["session_id": source.sessionID.uuidString, "owner_id": ownerID.uuidString,
            "build_attempt_id": source.buildAttemptID.uuidString, "material_id": source.materialID.uuidString,
            "app_source_manifest_sha256": source.appSourceManifestSHA256,
            "product_source_set_sha256": source.productSourceSetSHA256,
            "product_candidate_manifest_sha256": source.productCandidateManifestSHA256,
            "worker_input_plan_sha256": source.workerInputPlanSHA256, "recipe_sha256": source.recipeSHA256,
            "process": try r1OperationJSON(process), "root": root.path, "code": code.json]
        // Records consumption of this build's operation session. It is never
        // read as an allow file and cannot supply native GO or permit a retry.
        let consumed = code.home.appendingPathComponent(".orchard-build-" + source.buildAttemptID.uuidString.lowercased() + ".started.json")
        try exclusiveJobFileB(consumed, JSONSerialization.data(withJSONObject: context, options: [.sortedKeys]))
        guard fsync(homeFD) == 0 else { throw R1HumanSessionFault.evidence }
        guard mkdirat(homeFD, name, 0o700) == 0 else { throw R1HumanSessionFault.consumed }
        var created = [String: StampJobB]()
        let rootFD = try R1A12IO.openRoot(root)
        defer { _ = Darwin.close(rootFD) }
        created[""] = StampJobB(try statJobB(root))
        do {
            for child in ["store", "waiting", "extraction", "evidence"] {
                guard mkdirat(rootFD, child, 0o700) == 0 else { throw R1HumanSessionFault.resources }
                created[child] = StampJobB(try statJobB(root.appendingPathComponent(child)))
            }
            let lease: [String: Any] = ["schema": "orchard-r1-human-session-lease/1", "context": context,
                "directories": try r1OperationJSON(created), "normal_startup_does_not_inspect_or_extract": true]
            let leaseRaw = try JSONSerialization.data(withJSONObject: lease, options: [.sortedKeys])
            try R1A12IO.put(rootFD, "lease.json", leaseRaw)
            let leaseIdentity = StampJobB(try statJobB(root.appendingPathComponent("lease.json")))
            let ledger = try R1HumanOperationLedger(directory: root.appendingPathComponent("evidence"), context: context)
            try ledger.record("SESSION_ALLOCATED", ["directory_identities": try r1OperationJSON(created)])
            return R1HumanSessionResources(root: root, sessionID: source.sessionID, ownerID: ownerID,
                process: process, code: code, source: source, directories: created, ledger: ledger,
                leaseIdentity: leaseIdentity, leaseSHA256: hash54(leaseRaw))
        } catch {
            // At this stage there is no store or child. Remove only recorded,
            // still-empty directories. A partial evidence file is retained.
            for child in ["evidence", "extraction", "waiting", "store"] {
                if let expected = created[child], let actual = try? statJobB(root.appendingPathComponent(child)),
                   expected.directory(actual) { _ = unlinkat(rootFD, child, AT_REMOVEDIR) }
            }
            if let expected = created[""], let actual = try? statJobB(root), expected.directory(actual) {
                _ = unlinkat(homeFD, name, AT_REMOVEDIR)
            }
            throw error
        }
    }

    func verifyOwnerAndDirectories() throws {
        guard try R1HumanProcessStamp.current() == process, ledger.healthy else { throw R1HumanSessionFault.ownership }
        for (name, identity) in directories {
            let url = name.isEmpty ? root : root.appendingPathComponent(name, isDirectory: true)
            let fd = try R1A12IO.openRoot(url)
            defer { _ = Darwin.close(fd) }
            var value = stat()
            guard fstat(fd, &value) == 0, identity.directory(value),
                  identity.directory(try statJobB(url)) else { throw R1HumanSessionFault.ownership }
        }
        let lease = root.appendingPathComponent("lease.json")
        guard leaseIdentity.exact(try statJobB(lease)),
              hash54(try readJobFileB(lease, cap: 32_768)) == leaseSHA256 else { throw R1HumanSessionFault.ownership }
    }

    func verifyKnownRoot(extras: [R1HumanOwnedFile]) throws {
        try verifyOwnerAndDirectories()
        var expected: Set<String> = ["lease.json", "store", "waiting", "extraction", "evidence"]
        for extra in extras {
            guard extra.url.deletingLastPathComponent() == root,
                  extra.url.lastPathComponent.hasPrefix("observation-input-") else { throw R1HumanSessionFault.ownership }
            try extra.verify(); expected.insert(extra.url.lastPathComponent)
        }
        guard Set(try FileManager.default.contentsOfDirectory(atPath: root.path)) == expected else {
            throw R1HumanSessionFault.resources
        }
    }

    // Full own-root readback after quiescence is consumed by B/C's recovery
    // tool. Ready A12 output and evidence remain durable until that readback.
    func saveClosedReadback(resourcesReleased: Bool, retainedOutputs: [String], extras: [R1HumanOwnedFile]) throws {
        try verifyKnownRoot(extras: extras)
        try ledger.sealAndVerifyPrefix()
        var rows = [[String: Any]]()
        func walk(_ directory: URL, _ prefix: String, _ depth: Int) throws {
            guard depth <= 12 else { throw R1HumanSessionFault.resources }
            for name in try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() {
                guard !name.contains("/") && name != "." && name != ".." else { throw R1HumanSessionFault.resources }
                let url = directory.appendingPathComponent(name), st = try statJobB(url)
                let relative = prefix.isEmpty ? name : prefix + "/" + name
                guard st.st_uid == geteuid(), rows.count < 2048 else { throw R1HumanSessionFault.ownership }
                var row: [String: Any] = ["path": relative, "identity": try r1OperationJSON(StampJobB(st))]
                if st.st_mode & S_IFMT == S_IFDIR {
                    guard st.st_mode & 0o777 == 0o700 else { throw R1HumanSessionFault.ownership }
                    row["directory"] = true; rows.append(row)
                    try walk(url, relative, depth + 1)
                } else {
                    guard st.st_mode & S_IFMT == S_IFREG, st.st_nlink == 1,
                          [mode_t(0o400), mode_t(0o600)].contains(st.st_mode & 0o777),
                          st.st_size <= 8_388_608 else { throw R1HumanSessionFault.ownership }
                    let bytes = st.st_size == 0 ? try readJobFileB(url, cap: 8_388_608)
                        : try r1BoundedOwnedBytes(url, cap: 8_388_608)
                    row["directory"] = false; row["bytes"] = bytes.count; row["sha256"] = hash54(bytes)
                    rows.append(row)
                }
            }
        }
        try walk(root, "", 0)
        let row: [String: Any] = ["schema": "orchard-r1-human-session-closed/1", "root": root.path,
            "root_identity": try r1OperationJSON(directories[""]!), "session_id": sessionID.uuidString,
            "build_attempt_id": source.buildAttemptID.uuidString, "material_id": source.materialID.uuidString,
            "app_source_manifest_sha256": source.appSourceManifestSHA256,
            "product_source_set_sha256": source.productSourceSetSHA256,
            "process": try r1OperationJSON(process), "resources_released": resourcesReleased,
            "retained_ready_outputs": retainedOutputs, "inventory": rows,
            "evidence_and_output_retained_for_BC_readback": true, "restart_or_native_GO": false]
        let output = code.home.appendingPathComponent(".orchard-session-" + sessionID.uuidString.lowercased() + ".closed.json")
        try exclusiveJobFileB(output, JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]))
        let fd = Darwin.open(code.home.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard fd >= 0 else { throw R1HumanSessionFault.evidence }
        defer { _ = Darwin.close(fd) }
        guard fsync(fd) == 0 else { throw R1HumanSessionFault.evidence }
    }
}

// Reject links on the original route before binding its physical spelling.
// Foundation's path transformations are not evidence that the selected route
// was link-free.
private func r1DisallowedPhysicalZIPPath(_ path: String) -> Bool {
    ["/private/tmp", "/private/var", "/tmp", "/var"].contains { directory in
        path == directory || path.hasPrefix(directory + "/")
    }
}

private func r1NativeZIPPhysicalURL(_ original: URL) throws -> URL {
    guard original.isFileURL else { throw NativeInputRejectionB7b(stage: .url, code: .nonFileURL) }
    guard original.host == nil || original.host == "" else { throw NativeInputRejectionB7b(stage: .url, code: .remoteHost) }
    guard original.user == nil, original.password == nil, original.port == nil else {
        throw NativeInputRejectionB7b(stage: .url, code: .credentialsOrPort)
    }
    guard original.query == nil else { throw NativeInputRejectionB7b(stage: .url, code: .query) }
    guard original.fragment == nil else { throw NativeInputRejectionB7b(stage: .url, code: .fragment) }
    guard original.pathExtension.lowercased() == "zip" else { throw NativeInputRejectionB7b(stage: .url, code: .nonZIP) }
    let path = original.path
    guard path.hasPrefix("/"), !path.utf8.contains(0) else {
        throw NativeInputRejectionB7b(stage: .url, code: .invalidAbsolutePath)
    }
    let components = path.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
    guard !components.contains("."), !components.contains("..") else {
        throw NativeInputRejectionB7b(stage: .url, code: .dotComponent)
    }
    guard !components.contains("") else { throw NativeInputRejectionB7b(stage: .url, code: .emptyComponent) }
    guard !["/tmp", "/var"].contains(where: { path.hasPrefix($0 + "/") }) else {
        throw NativeInputRejectionB7b(stage: .alias, code: .aliasDisallowed)
    }
    let route = path
    var selected = stat()
    guard lstat(path, &selected) == 0 else {
        throw NativeInputRejectionB7b(stage: .selectedFile, code: .selectedLookupFailed, systemErrno: errno)
    }
    guard selected.st_mode & S_IFMT != S_IFLNK else {
        throw NativeInputRejectionB7b(stage: .selectedFile, code: .symlinkDisallowed)
    }
    guard selected.st_mode & S_IFMT == S_IFREG else {
        throw NativeInputRejectionB7b(stage: .selectedFile, code: .nonRegularFile)
    }
    guard selected.st_nlink == 1 else { throw NativeInputRejectionB7b(stage: .selectedFile, code: .multipleLinks) }
    let aliasFile: Bool
    do {
        guard let value = try original.resourceValues(forKeys: [.isAliasFileKey]).isAliasFile else {
            throw NativeInputRejectionB7b(stage: .alias, code: .aliasLookupFailed)
        }
        aliasFile = value
    } catch let rejection as NativeInputRejectionB7b {
        throw rejection
    } catch {
        throw NativeInputRejectionB7b(stage: .alias, code: .aliasLookupFailed)
    }
    guard !aliasFile else { throw NativeInputRejectionB7b(stage: .alias, code: .aliasDisallowed) }
    var firstFD: Int32 = -1, physicalFD: Int32 = -1, finalRouteFD: Int32 = -1
    func closeDescriptors() -> [Int32] {
        let descriptors = [finalRouteFD, physicalFD, firstFD]
        finalRouteFD = -1; physicalFD = -1; firstFD = -1
        var failures = [Int32]()
        for fd in descriptors where fd >= 0 {
            if Darwin.close(fd) != 0 { failures.append(errno) }
        }
        return failures
    }
    do {
        firstFD = Darwin.open(route, O_RDONLY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC)
        guard firstFD >= 0 else {
            let failure = errno
            throw NativeInputRejectionB7b(stage: .selectedFile,
                code: failure == ELOOP ? .symlinkDisallowed : .routeOpenFailed, systemErrno: failure)
        }
        var opened = stat(), resolved = stat(), after = stat(), named = stat()
        guard fstat(firstFD, &opened) == 0 else {
            throw NativeInputRejectionB7b(stage: .selectedFile, code: .routeStatFailed, systemErrno: errno)
        }
        guard FileIdentity54(selected).unchanged(opened) else {
            throw NativeInputRejectionB7b(stage: .selectedFile, code: .selectedIdentityMismatch)
        }
        guard let resolvedBytes = realpath(route, nil) else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .realpathFailed, systemErrno: errno)
        }
        let physicalPath = String(cString: resolvedBytes)
        free(resolvedBytes)
        guard !r1DisallowedPhysicalZIPPath(physicalPath) else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .physicalLocationDisallowed)
        }
        let physical = URL(fileURLWithPath: physicalPath, isDirectory: false)
        physicalFD = Darwin.open(physical.path, O_RDONLY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC)
        guard physicalFD >= 0 else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .physicalOpenFailed, systemErrno: errno)
        }
        guard fstat(physicalFD, &resolved) == 0 else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .physicalStatFailed, systemErrno: errno)
        }
        guard FileIdentity54(selected).unchanged(resolved) else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .physicalIdentityMismatch)
        }
        // A parent replaced by a symlink after the first open must still fail,
        // even when it leads to the very same inode at the physical spelling.
        finalRouteFD = Darwin.open(route, O_RDONLY | O_NOFOLLOW_ANY | O_NONBLOCK | O_CLOEXEC)
        guard finalRouteFD >= 0 else {
            let failure = errno
            throw NativeInputRejectionB7b(stage: .selectedFile,
                code: failure == ELOOP ? .symlinkDisallowed : .routeOpenFailed, systemErrno: failure)
        }
        guard lstat(path, &named) == 0 else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .finalLookupFailed, systemErrno: errno)
        }
        var finalRoute = stat()
        guard fstat(firstFD, &after) == 0, fstat(physicalFD, &resolved) == 0,
              fstat(finalRouteFD, &finalRoute) == 0 else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .finalStatFailed, systemErrno: errno)
        }
        let identity = FileIdentity54(selected)
        guard identity.unchanged(named), identity.unchanged(after), identity.unchanged(resolved),
              identity.unchanged(finalRoute) else {
            throw NativeInputRejectionB7b(stage: .physicalFile, code: .fileChanged)
        }
        let failures = closeDescriptors()
        guard failures.isEmpty else {
            throw NativeInputRejectionB7b(stage: .closure, code: .descriptorCloseFailed,
                systemErrno: failures.first, cleanupErrnos: failures)
        }
        return physical
    } catch {
        var rejection = (error as? NativeInputRejectionB7b) ??
            NativeInputRejectionB7b(stage: .provider, code: .unexpectedProviderFailure)
        let failures = closeDescriptors()
        if !failures.isEmpty { rejection.cleanupErrnos = failures }
        throw rejection
    }
}

@MainActor
final class R1HumanOperationAdmission: @MainActor R1FreshProductAdmission {
    let configuration: R1ProductLaunchConfiguration
    let resources: R1HumanSessionResources
    weak var flow: R1ProductFlow?
    private var active = true
    private var extractionKeys = [UUID: R1ProductReviewKey]()
    private var extractionJobs = Set<UUID>()

    init(configuration: R1ProductLaunchConfiguration, resources: R1HumanSessionResources) {
        self.configuration = configuration; self.resources = resources
    }
    func close() { active = false }
    func verifyCurrentNativeScope() throws {
        guard active else { throw NativeInputRejectionB7b(stage: .session, code: .inactiveSession) }
        guard configuration.sessionID == resources.sessionID else {
            throw NativeInputRejectionB7b(stage: .session, code: .sessionMismatch)
        }
        do { try resources.verifyOwnerAndDirectories() }
        catch { throw NativeInputRejectionB7b(stage: .freshScope, code: .ownerEvidenceRejected) }
        do { try resources.code.verifyCurrent() }
        catch { throw NativeInputRejectionB7b(stage: .freshScope, code: .runningCodeRejected) }
    }
    func verifyR1ProductScope() throws {
        try verifyCurrentNativeScope()
        do { try configuration.validateLayout() }
        catch { throw NativeInputRejectionB7b(stage: .freshScope, code: .layoutRejected) }
        do { try configuration.validateManifest() }
        catch { throw NativeInputRejectionB7b(stage: .manifest, code: .manifestRejected) }
        do { try R1ProductAppEntry.validateV7Registration(rootURL: configuration.rootURL, registration: configuration.registration) }
        catch { throw NativeInputRejectionB7b(stage: .freshScope, code: .registrationRejected) }
        guard configuration.executionSource == resources.source,
              configuration.sessionID == resources.sessionID,
              configuration.registration.ownerID == resources.ownerID else {
            throw NativeInputRejectionB7b(stage: .freshScope, code: .operationSourceMismatch)
        }
    }
    func verifyFreshLaunch(configuration: R1ProductLaunchConfiguration) throws {
        try verifyR1ProductScope()
        guard configuration.executionSource == self.configuration.executionSource,
              configuration.registration.ownerID == self.configuration.registration.ownerID,
              configuration.registration.storeID == self.configuration.registration.storeID,
              configuration.registration.anchorSHA256 == self.configuration.registration.anchorSHA256,
              configuration.rootURL == resources.store, configuration.waitingURL == resources.waiting,
              configuration.extractionRootURL == resources.extraction,
              configuration.appBundle == resources.code.bundleURL,
              configuration.worker.signedExecutableSHA256 == resources.code.workerSHA256,
              configuration.worker.executableBytes == resources.code.workerBytes else {
            throw NativeInputRejectionB7b(stage: .freshScope, code: .freshBindingMismatch)
        }
    }
    func admitCurrentZIP(_ original: URL, sessionID: UUID) throws -> URL? {
        do { try verifyFreshLaunch(configuration: configuration) }
        catch let rejection as NativeInputRejectionB7b { throw rejection }
        catch { throw NativeInputRejectionB7b(stage: .session, code: .admissionScopeRejected) }
        guard sessionID == resources.sessionID else {
            throw NativeInputRejectionB7b(stage: .session, code: .sessionMismatch)
        }
        guard let flow else { throw NativeInputRejectionB7b(stage: .session, code: .flowUnavailable) }
        guard flow.canAcceptInput else { throw NativeInputRejectionB7b(stage: .session, code: .flowNotReady) }
        // B8 owns the original AppKit URL access, bounded copy, metadata and
        // input SHA/identity checks. Selection never starts inspection.
        return try r1NativeZIPPhysicalURL(original)
    }
    func verifyLimitedExtraction(binding: R1ProductBinding, attemptID: UUID, destinationRoot: URL) throws {
        try verifyFreshLaunch(configuration: configuration)
        guard let flow, !flow.isInspecting, flow.workerQuiescent, !flow.stopping, !flow.operationsHeld,
              let current = flow.binding, let operation = binding.operationIdentity,
              operation.matches(source: resources.source, registration: configuration.registration),
              R1ProductReviewKey(current) == R1ProductReviewKey(binding), flow.currentJobID == binding.jobID,
              binding.sessionID == resources.sessionID, binding.ownerID == resources.ownerID,
              binding.storeID == configuration.registration.storeID,
              binding.workerDirectReap, binding.workerPipeFDsClosed, binding.inputFDClosedAfterReturn,
              binding.workerJSONStatus == "VALID",
              flow.session?.snapshot(now: flow.currentReviewTime()).decision == R1ReviewDecision.confirmed.rawValue,
              destinationRoot == resources.extraction,
              ![operation.inspectionAttemptID, operation.sessionID, operation.buildAttemptID,
                operation.materialID, operation.ownerID, operation.storeID].contains(attemptID) else {
            throw R1FreshProductFault.confirmation
        }
        let key = R1ProductReviewKey(binding)
        if let old = extractionKeys[attemptID] {
            guard old == key else { throw R1FreshProductFault.confirmation }
        } else {
            guard extractionJobs.insert(binding.jobID).inserted else { throw R1A11Fault.attempt }
            extractionKeys[attemptID] = key
            try resources.ledger.record("EXTRACTION_BOUND", ["attempt_id": attemptID.uuidString,
                "binding": try r1OperationJSON(binding), "destination": destinationRoot.path])
        }
    }
}

@MainActor
final class R1HumanOperationSession {
    let resources: R1HumanSessionResources
    let admission: R1HumanOperationAdmission
    private weak var session: R1FreshProductSession?
    private var shutdownCompletion: ((Bool) -> Void)?
    private var shuttingDown = false, shutdownFinished = false
    private var observationAttempted = false
    private var observationInputs = [R1HumanOwnedFile]()

    private init(resources: R1HumanSessionResources, admission: R1HumanOperationAdmission) {
        self.resources = resources; self.admission = admission
    }

    static func prepare() throws -> R1FreshProductSession {
        let code = try R1HumanCodeObservation.capture()
        let manifest = try R1AppSourceBinding.read(in: code.bundleURL)
        let sessionID = UUID(), ownerID = UUID()
        let source = try manifest.executionSource(sessionID: sessionID)
        guard ![source.materialID, source.buildAttemptID, sessionID].contains(ownerID) else {
            throw R1HumanSessionFault.source
        }
        let resources = try R1HumanSessionResources.allocate(code: code, source: source, ownerID: ownerID)
        do {
            let registration = try PersistentJobsB.create(root: resources.store, waiting: resources.waiting,
                ownerID: ownerID, limits: QueueLimitsB(retainedJobs: 4, waitingJobs: 3, retainedBytes: 33_554_432),
                nativeProductQualification: true)
            let configuration = try manifest.launchConfiguration(rootURL: resources.store, waitingURL: resources.waiting,
                extractionRootURL: resources.extraction, registration: registration, sessionID: sessionID,
                appBundle: code.bundleURL, signedWorkerSHA256: code.workerSHA256, workerBytes: code.workerBytes)
            let admission = R1HumanOperationAdmission(configuration: configuration, resources: resources)
            let session = try R1FreshProductSession.prepare(configuration: configuration, admission: admission,
                runtimeRevalidate: { try code.verifyCurrent(); try resources.verifyOwnerAndDirectories() })
            let operations = R1HumanOperationSession(resources: resources, admission: admission)
            operations.session = session; session.humanOperations = operations
            let flow = session.entry.composition.flow
            admission.flow = flow; flow.operationSource = source
            let ledger = resources.ledger
            flow.workerLedger = ledger
            flow.onOperationEvent = { stage, details in try ledger.record(stage, details) }
            flow.onInspectionFinished = { [weak operations, weak session] in
                session?.entry.composition.screen.refresh()
                if operations?.shuttingDown == true { operations?.finishShutdown() }
            }
            session.extraction.operationEvent = { stage, details in try ledger.record(stage, details) }
            session.extraction.operationReady = { [weak flow, weak operations] in
                operations?.shuttingDown == false && flow?.canAcceptInput == true
            }
            try ledger.record("SESSION_CONNECTED", ["registration": try r1OperationJSON(registration),
                "code": code.json, "startup_worker_starts": 0, "startup_extractions": 0,
                "session_id": source.sessionID.uuidString, "build_attempt_id": source.buildAttemptID.uuidString,
                "product_source_set_sha256": source.productSourceSetSHA256])
            return session
        } catch {
            try? resources.ledger.record("INITIALIZATION_HOLD", ["error": String(describing: error),
                "RESOURCE_REMAINS": true, "automatic_retry": false])
            if let root = ProcessBootstrapOwnerB7b.retained, root.applicationOwner.store.root == resources.store {
                try? root.applicationOwner.applicationQuit()
                try? ProcessBootstrapOwnerB7b.releaseClosedOwner(root.applicationOwner)
            }
            // Preserve partial-store identity evidence. No guessing deletion.
            throw error
        }
    }

    func recordSandboxObservation() {
        guard !observationAttempted, !shuttingDown, let session,
              session.entry.composition.flow.canAcceptInput else { return }
        observationAttempted = true
        let flow = session.entry.composition.flow
        do {
            try admission.verifyFreshLaunch(configuration: admission.configuration)
            let work = try R1SandboxObservationWork(resources: resources, configuration: admission.configuration)
            observationInputs.append(work.inputPin)
            try flow.beginObservation()
            flow.onStopObservation = { work.stop.request("OPERATION_OWNER_STOP") }
            session.entry.composition.screen.refresh()
            DispatchQueue(label: "Orchard.R1.SandboxObservation").async {
                work.run()
                DispatchQueue.main.async { [self] in
                    var passed = false
                    do {
                        guard !work.stop.requested, work.resourcesQuiescent, let result = work.result else {
                            throw R1HumanSessionFault.resources
                        }
                        var observations = try result.get()
                        observations["closure"] = ["parent_FDs_closed": work.parentFDsClosed,
                            "input_FD_closed": work.inputFDClosed, "pin_FD_closed": work.pinFDClosed,
                            "worker_quiescent": work.port.resourcesQuiescent]
                        try resources.ledger.record("G1_SANDBOX_OBSERVATION", observations)
                        passed = true
                    } catch {
                        try? resources.ledger.record("G1_SANDBOX_OBSERVATION_HOLD", ["reason": String(describing: error),
                            "worker_resources": work.port.resourceReadback, "parent_FDs_closed": work.parentFDsClosed,
                            "input_FD_closed": work.inputFDClosed, "pin_FD_closed": work.pinFDClosed])
                    }
                    flow.finishObservation(starts: work.port.starts, quiescent: work.resourcesQuiescent, passed: passed)
                    session.entry.composition.screen.refresh()
                    if shuttingDown { finishShutdown() }
                }
            }
        } catch {
            flow.holdOperations("動作状態の記録を開始できませんでした。")
            try? resources.ledger.record("G1_OBSERVATION_PREPARE_HOLD", ["reason": String(describing: error)])
            session.entry.composition.screen.refresh()
        }
    }

    func shutdown(completion: @escaping (Bool) -> Void) {
        guard !shuttingDown, !shutdownFinished, let session else { completion(shutdownFinished); return }
        shuttingDown = true; shutdownCompletion = completion
        session.entry.composition.screen.requestZIPSelection = nil
        session.extraction.requestShutdown()
        session.entry.composition.flow.requestStop("APPLICATION_QUIT")
        session.entry.composition.screen.refresh()
        if !session.entry.composition.flow.isInspecting && !session.entry.composition.flow.observationBusy { finishShutdown() }
    }

    private func finishShutdown() {
        guard shuttingDown, !shutdownFinished, let session else { return }
        let flow = session.entry.composition.flow, owner = session.entry.composition.root.applicationOwner
        guard !flow.isInspecting, !flow.observationBusy, flow.workerQuiescent else {
            try? resources.ledger.record("SHUTDOWN_RESOURCE_HOLD", ["worker_quiescent": flow.workerQuiescent])
            shutdownCompletion?(false); shutdownCompletion = nil; return
        }
        var failure: Error?, outputs = [String]()
        do {
            try resources.verifyOwnerAndDirectories()
            try resources.verifyKnownRoot(extras: observationInputs)
            try resources.ledger.record("SHUTDOWN_STARTED", ["state": try r1OperationJSON(flow.snapshot())])
            var extractionNames = Set<String>()
            for attempt in session.extraction.allAttemptIDs {
                let intent = resources.extraction.appendingPathComponent(R1A12Transaction.intentName(attempt))
                var state = stat()
                if lstat(intent.path, &state) != 0 {
                    guard errno == ENOENT else { throw R1HumanSessionFault.resources }
                    try resources.ledger.record("EXTRACTION_NO_INTENT", ["attempt_id": attempt.uuidString])
                    continue
                }
                let assessment = try R1A12Recovery.assess(root: resources.extraction, attemptID: attempt)
                try resources.ledger.record("A12_SHUTDOWN_ASSESSMENT", r1OperationJSON(assessment))
                if assessment.ready {
                    if let folder = assessment.folder { outputs.append(folder) }
                    extractionNames.insert(R1A12Transaction.intentName(attempt))
                    extractionNames.insert(R1A12Transaction.folderName(attempt))
                } else if assessment.cleanupAllowed && assessment.status == "HOLD_INCOMPLETE" {
                    _ = try R1A12Recovery.cleanupIncomplete(root: resources.extraction, attemptID: attempt)
                    extractionNames.insert(R1A12Transaction.closedName(attempt))
                    try resources.ledger.record("A12_INCOMPLETE_CLEANED", ["attempt_id": attempt.uuidString])
                } else { throw R1HumanSessionFault.resources }
            }
            guard Set(try FileManager.default.contentsOfDirectory(atPath: resources.extraction.path)) == extractionNames,
                  Set(try FileManager.default.contentsOfDirectory(atPath: resources.store.path)) ==
                    Set(["anchor.json", "owner.lock", "events.jsonl"]) else { throw R1HumanSessionFault.resources }
            let anchorRaw = try readJobFileB(resources.store.appendingPathComponent("anchor.json"), cap: 8192)
            let anchor = try decodeJobB(StoreAnchorJobB.self, anchorRaw)
            guard hash54(anchorRaw) == owner.store.registration.anchorSHA256,
                  anchor.lock.object(try statJobB(resources.store.appendingPathComponent("owner.lock"))),
                  anchor.journal.object(try statJobB(resources.store.appendingPathComponent("events.jsonl"))) else {
                throw R1HumanSessionFault.ownership
            }
            for row in owner.snapshots().map(\.job) where row.artifact != nil && row.cleanup != "REMOVED" {
                if [.receiving, .accepted, .waiting, .inspecting].contains(row.state) { try owner.cancel(row.jobID) }
                try owner.recoverOwnedCopy(row.jobID)
            }
            guard try FileManager.default.contentsOfDirectory(atPath: resources.waiting.path).isEmpty else {
                throw R1HumanSessionFault.resources
            }
            try resources.ledger.record("OWNED_INPUTS_RECLAIMED", ["waiting_remaining": 0, "worker_quiescent": true])
        } catch { failure = error }
        admission.close()
        session.entry.composition.screen.stopReviewRefresh()
        if !session.entry.composition.root.applicationDelegate.prepareQuit(), failure == nil {
            failure = R1HumanSessionFault.resources
        }
        do { try ProcessBootstrapOwnerB7b.releaseClosedOwner(owner) } catch { if failure == nil { failure = error } }
        do {
            try resources.ledger.record("SESSION_CLOSED", ["store_closed": owner.store.isClosed,
                "worker_quiescent": flow.workerQuiescent, "retained_ready_outputs": outputs,
                "RESOURCE_REMAINS": failure != nil, "error": failure.map(String.init(describing:)) as Any? ?? NSNull()])
            try resources.saveClosedReadback(resourcesReleased: failure == nil && owner.store.isClosed,
                                             retainedOutputs: outputs, extras: observationInputs)
        } catch { if failure == nil { failure = error } }
        shutdownFinished = failure == nil && owner.store.isClosed
        shutdownCompletion?(shutdownFinished); shutdownCompletion = nil
    }
}
