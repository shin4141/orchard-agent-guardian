// G1 observations only, requested through an explicit product menu action.
// This never launches an app, changes Sandbox/TCC, or feeds a review/extractor.
import Foundation
import Darwin

struct R1SandboxObservationPlan: Decodable {
    let schema: String, buildAttemptID: String, materialID: String, bundleIdentifier: String
    let canaryPath: String, canarySHA256: String
    let canaryBytes: Int, networkHost: String, networkPort: Int
    let authorizesActions: Bool
    enum CodingKeys: String, CodingKey {
        case schema
        case buildAttemptID = "build_attempt_id", materialID = "material_id", bundleIdentifier = "bundle_identifier"
        case canaryPath = "canary_path", canarySHA256 = "canary_sha256", canaryBytes = "canary_bytes"
        case networkHost = "network_host", networkPort = "network_port", authorizesActions = "authorizes_actions"
    }
    static func read(resources: R1HumanSessionResources) throws -> (R1SandboxObservationPlan, Data) {
        try resources.code.verifyCurrent()
        let url = resources.code.bundleURL.appendingPathComponent("Contents/Resources/OrchardProduct/ObservationPlan.json")
        let raw = try readJobFileB(url, cap: 4096)
        let plan = try JSONDecoder().decode(Self.self, from: raw)
        let build = resources.source.buildAttemptID.uuidString.lowercased().replacingOccurrences(of: "-", with: "")
        let material = resources.source.materialID.uuidString.lowercased().replacingOccurrences(of: "-", with: "")
        guard plan.schema == "orchard-r1-sandbox-observation-plan/1", !plan.authorizesActions,
              plan.buildAttemptID == build, plan.materialID == material,
              plan.bundleIdentifier == resources.code.bundleIdentifier,
              plan.canaryPath == "/private/tmp/orchard-r1-" + build + "-probe/canary.txt",
              R1AppSourceBinding.hex(plan.canarySHA256, 64), plan.canaryBytes > 0, plan.canaryBytes <= 4096,
              plan.networkHost == "127.0.0.1", plan.networkPort == 9 else { throw R1HumanSessionFault.source }
        return (plan, raw)
    }
}

enum R1SandboxObservation {
    // Literal, B/C-owned diagnostic code. Input is bounded sealed plan data;
    // archive text is never used as code, argv or an environment variable.
    static let workerProgram = #"""
import errno, hashlib, json, os, socket, sys
raw = sys.stdin.buffer.read(4097)
if not 0 < len(raw) <= 4096:
    raise SystemExit(3)
p = json.loads(raw)
b = p['build_attempt_id']
if (len(b) != 32 or any(c not in '0123456789abcdef' for c in b)
    or p['schema'] != 'orchard-r1-sandbox-observation-plan/1'
    or p['authorizes_actions'] is not False
    or p['canary_path'] != '/private/tmp/orchard-r1-' + b + '-probe/canary.txt'
    or p['network_host'] != '127.0.0.1' or p['network_port'] != 9):
    raise SystemExit(3)
rows = []
for label, mode in [('FILE_READ_OPEN', os.O_RDONLY), ('FILE_WRITE_OPEN', os.O_WRONLY)]:
    fd = None
    try:
        fd = os.open(p['canary_path'], mode | os.O_NOFOLLOW | os.O_CLOEXEC)
        rows.append({'operation': label, 'denied': False, 'errno': 0, 'bytes_transferred': 0})
    except OSError as e:
        rows.append({'operation': label, 'denied': e.errno in (errno.EPERM, errno.EACCES), 'errno': e.errno, 'bytes_transferred': 0})
    finally:
        if fd is not None:
            os.close(fd)
for label in ['NETWORK_LISTEN', 'NETWORK_CONNECT']:
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        if label == 'NETWORK_LISTEN':
            s.bind(('127.0.0.1', 0))
            s.listen(1)
        else:
            s.connect(('127.0.0.1', 9))
        rows.append({'operation': label, 'denied': False, 'errno': 0, 'bytes_transferred': 0})
    except OSError as e:
        rows.append({'operation': label, 'denied': e.errno in (errno.EPERM, errno.EACCES), 'errno': e.errno, 'bytes_transferred': 0})
    finally:
        if s is not None:
            s.close()
print(json.dumps({'schema': 'orchard-r1-sandbox-observation/1', 'input_sha256': hashlib.sha256(raw).hexdigest(),
    'input_bytes': len(raw), 'observations': rows, 'authorizes_actions': False}, ensure_ascii=True, sort_keys=True))
"""#

    static func parent(plan: R1SandboxObservationPlan, stop: R1WorkerCancellation,
                       allClosed: inout Bool) throws -> [[String: Any]] {
        var rows = [[String: Any]]()
        for (label, flags) in [("FILE_READ_OPEN", O_RDONLY), ("FILE_WRITE_OPEN", O_WRONLY)] {
            guard !stop.requested else { throw R1WorkerPortFault.cancelled }
            errno = 0
            let fd = Darwin.open(plan.canaryPath, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            let error = errno
            if fd >= 0 { allClosed = Darwin.close(fd) == 0 && allClosed }
            rows.append(["operation": label, "denied": fd < 0 && (error == EPERM || error == EACCES),
                         "errno": fd < 0 ? Int(error) : 0, "bytes_transferred": 0])
        }
        for label in ["NETWORK_LISTEN", "NETWORK_CONNECT"] {
            guard !stop.requested else { throw R1WorkerPortFault.cancelled }
            errno = 0
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            if fd < 0 {
                let error = errno
                rows.append(["operation": label, "denied": error == EPERM || error == EACCES,
                    "errno": Int(error), "bytes_transferred": 0])
                continue
            }
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = in_port_t(label == "NETWORK_LISTEN" ? 0 : plan.networkPort).bigEndian
            guard inet_pton(AF_INET, plan.networkHost, &address.sin_addr) == 1,
                  fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else {
                allClosed = Darwin.close(fd) == 0 && allClosed
                throw R1HumanSessionFault.input
            }
            errno = 0
            var result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    label == "NETWORK_LISTEN" ? Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                        : Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if result == 0 && label == "NETWORK_LISTEN" { result = Darwin.listen(fd, 1) }
            let error = errno
            allClosed = Darwin.close(fd) == 0 && allClosed
            rows.append(["operation": label, "denied": result < 0 && (error == EPERM || error == EACCES),
                         "errno": result < 0 ? Int(error) : 0, "bytes_transferred": 0])
        }
        return rows
    }

    static func allDenied(_ rows: [[String: Any]]) -> Bool {
        let names: Set<String> = ["FILE_READ_OPEN", "FILE_WRITE_OPEN", "NETWORK_LISTEN", "NETWORK_CONNECT"]
        return rows.count == 4 && Set(rows.compactMap { $0["operation"] as? String }) == names &&
            rows.allSatisfy { row in
                row["denied"] as? Bool == true && [Int(EPERM), Int(EACCES)].contains(row["errno"] as? Int ?? -1)
                    && row["bytes_transferred"] as? Int == 0
            }
    }
}

// Same single-worker ownership handoff as inspection. This result can never
// become a ZIP review, confirmation or extraction binding.
final class R1SandboxObservationWork: @unchecked Sendable {
    let stop = R1WorkerCancellation()
    let attemptID: UUID
    let input: URL, inputBytes: Data, plan: R1SandboxObservationPlan
    let inputPin: R1HumanOwnedFile
    let port: R1WorkerProcessPort
    let resources: R1HumanSessionResources
    let operation: R1ProductOperationIdentity
    private(set) var result: Result<[String: Any], Error>?
    private(set) var parentFDsClosed = true, inputFDClosed = true, pinFDClosed = true
    var resourcesQuiescent: Bool { parentFDsClosed && inputFDClosed && pinFDClosed && port.resourcesQuiescent }

    init(resources: R1HumanSessionResources, configuration: R1ProductLaunchConfiguration) throws {
        self.resources = resources
        let loaded = try R1SandboxObservationPlan.read(resources: resources)
        plan = loaded.0; inputBytes = loaded.1
        attemptID = UUID()
        operation = R1ProductOperationIdentity(source: resources.source, registration: configuration.registration,
                                               inspectionAttemptID: attemptID)
        input = resources.root.appendingPathComponent("observation-input-" + attemptID.uuidString.lowercased() + ".json")
        try exclusiveJobFileB(input, inputBytes)
        inputPin = try R1HumanOwnedFile(url: input, expected: inputBytes)
        let runtime = try R1WorkerRuntime.freshBundled(in: configuration.appBundle, binding: configuration.worker,
            sessionID: configuration.sessionID, revalidate: {
                try resources.code.verifyCurrent(); try resources.verifyOwnerAndDirectories()
            })
        let observationRuntime = R1WorkerRuntime(executable: runtime.executable,
            argvTail: ["-P", "-S", "-B", "-c", R1SandboxObservation.workerProgram],
            environment: runtime.environment, engine: runtime.engine,
            expectedExecutableSHA256: runtime.expectedExecutableSHA256,
            label: "FRESH_WORKER_G1_OBSERVATION_ONLY_NOT_ZIP_INSPECTION",
            validateFreshAtUse: { try runtime.validateBeforeSpawn() })
        port = R1WorkerProcessPort(runtime: observationRuntime)
        try resources.ledger.record("SANDBOX_OBSERVATION_STARTED", ["operation": try r1OperationJSON(operation),
            "input_path": input.path, "input_sha256": hash54(inputBytes), "input_bytes": inputBytes.count,
            "input_identity": try r1OperationJSON(inputPin.identity), "authorizes_actions": false])
    }

    func run() {
        result = Result {
            try resources.code.verifyCurrent(); try resources.verifyOwnerAndDirectories()
            guard !stop.requested else { throw R1WorkerPortFault.cancelled }
            let parent = try R1SandboxObservation.parent(plan: plan, stop: stop, allClosed: &parentFDsClosed)
            try resources.ledger.record("PARENT_SANDBOX_OBSERVATION", ["observations": parent, "FDs_closed": parentFDsClosed])
            guard parentFDsClosed, R1SandboxObservation.allDenied(parent), !stop.requested else {
                throw R1HumanSessionFault.resources
            }
            let fd = Darwin.open(input.path, O_RDONLY | O_NOFOLLOW_ANY | O_CLOEXEC)
            guard fd >= 0 else { throw R1HumanSessionFault.input }
            inputFDClosed = false
            defer { inputFDClosed = Darwin.close(fd) == 0 }
            var identity = stat()
            guard fstat(fd, &identity) == 0, identity.st_size == inputBytes.count,
                  try readJobFileB(input, cap: 4096) == inputBytes else { throw R1HumanSessionFault.input }
            let pin = try PinnedRead54(url: input, size: Int64(inputBytes.count), sha256: hash54(inputBytes))
            pinFDClosed = false
            defer { pinFDClosed = pin.closeOwned() }
            try pin.openAndPin(selectedFD: fd, selectedIdentity: FileIdentity54(identity)) {}
            let operationJSON = try r1OperationJSON(operation)
            let raw = try port.runOnce(inputFD: fd, inputBytes: Int64(inputBytes.count), inputSHA256: hash54(inputBytes),
                cancellation: stop, processEvent: { event in
                    try self.resources.ledger.record("WORKER_PROCESS", ["operation": operationJSON,
                        "purpose": "SANDBOX_OBSERVATION_ONLY", "event": event])
                })
            try pin.verifyPathAndFD()
            try resources.ledger.record("WORKER_SANDBOX_RECEIPT", ["operation": operationJSON,
                "receipt_sha256": hash54(raw), "receipt_base64": raw.base64EncodedString()])
            guard !stop.requested, let receipt = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
                  receipt["waitpid_reaped"] as? Bool == true, receipt["all_created_pipe_fds_closed"] as? Bool == true,
                  receipt["start_identity_valid"] as? Bool == true, receipt["exit_code"] as? Int == 0,
                  let stdout = (receipt["stdout_ascii"] as? String)?.data(using: .ascii),
                  let report = try JSONSerialization.jsonObject(with: stdout) as? [String: Any],
                  report["schema"] as? String == "orchard-r1-sandbox-observation/1",
                  report["authorizes_actions"] as? Bool == false,
                  report["input_sha256"] as? String == hash54(inputBytes), report["input_bytes"] as? Int == inputBytes.count,
                  let child = report["observations"] as? [[String: Any]], R1SandboxObservation.allDenied(child) else {
                throw R1HumanSessionFault.resources
            }
            return ["parent": parent, "worker": child, "same_signed_worker": true,
                    "ZIP_review_or_extraction_created": false, "authorizes_actions": false]
        }
    }
}
