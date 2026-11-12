// A9 product source: the only inspection request is for the current B8-owned
// waiting job and its pinned copied ZIP FD. No old interrupted job is resumed.
import Foundation
import Darwin

enum R1ProductFault: String, Error {
    case noCurrentJob, staleOrInterrupted, alreadyAttempted, inputBinding, workerContract
}

struct R1ProductBinding: Encodable {
    let ownerID: UUID
    let storeID: UUID
    let sessionID: UUID
    let jobID: UUID
    let jobRevision: Int
    let intakeInputID: UUID
    let intakeAttemptID: UUID
    let sourceKey: String
    let copiedZIPSize: Int64
    let copiedZIPSHA256: String
    let copiedZIPDevice: Int64
    let copiedZIPInode: UInt64
    let copiedZIPUID: UInt32
    let workerReceiptSHA256: String
    let workerPID: Int?
    let workerJSONStatus: String
    let workerDirectReap: Bool
    let workerPipeFDsClosed: Bool
    let inputFDClosedAfterReturn: Bool
    let displayedInputSHA256: String
    let aiHandoffCreated = false
    let actualExtractionPerformed = false
    var operationIdentity: R1ProductOperationIdentity? = nil
}

struct R1ProductState: Encodable {
    let currentJobID: UUID?
    let currentInputSHA256: String?
    let workerStarts: Int
    let reviewDecision: String
    let inspectionStatus: String
    let promptInjection: String
    let confirmEnabled: Bool
    let mockLabel: String?
    let aiHandoffCreated = false
    let actualExtractionPerformed = false
    let handoffGate = "HOLD"
    let issue: String?
    let binding: R1ProductBinding?
}

private func r1VisibleIngressReason(_ item: IngressItemB7b) -> String {
    if let code = item.nativeInputRejection?.code {
        switch code {
        case .aliasDisallowed, .aliasLookupFailed, .aliasNotTrusted, .aliasTargetMismatch, .aliasChanged:
            return "エイリアス経由のZIPは選択できません。"
        case .symlinkDisallowed:
            return "シンボリックリンク経由のZIPは選択できません。"
        case .multipleLinks:
            return "ハードリンクされたZIPは選択できません。"
        case .physicalLocationDisallowed:
            return "この場所のZIPは選択できません。"
        case .nonZIP:
            return "ZIPファイルを選択してください。"
        case .nonRegularFile:
            return "通常のZIPファイルを選択してください。"
        case .fileChanged, .selectedIdentityMismatch, .physicalIdentityMismatch:
            return "選択したファイルが変わったため受け付けられません。"
        default:
            return "ZIPの安全確認ができなかったため受け付けられません。"
        }
    }
    if item.reason == "ZIP_ROUTE_ONLY_NOT_FORMAT_PROOF" { return "ZIPファイルを選択してください。" }
    return "ZIPを受け付けられませんでした。"
}

private struct R1InspectionOutcome {
    let job: RecordJobB
    let receipt: Data
    let identity: FileIdentity54
    let inputFDClosed: Bool
}

// ApplicationJobsB already serializes its store and holds the pinned FD for
// the complete body. The UI's async request uses this same receiver/port.
private func r1InspectOwnedZIP(owner: ApplicationJobsB, id: UUID, port: R1WorkerProcessPort,
    processDeadline: Double, sendBytes: Int64?, holdInputOpen: Bool,
    cancellation: R1WorkerCancellation? = nil,
    processEvent: (([String: Any]) throws -> Void)? = nil) throws -> R1InspectionOutcome {
    var capturedFD: Int32 = -1
    let (job, raw, identity) = try owner.withCurrentWaitingZIP(id) { row, fd, identity in
        capturedFD = fd
        guard row.jobID == id, let artifact = row.artifact,
              row.storeID == owner.store.registration.storeID,
              row.ownerID == owner.store.registration.ownerID,
              artifact.size == identity.size else { throw R1ProductFault.inputBinding }
        let raw = try port.runOnce(inputFD: fd, inputBytes: artifact.size,
            inputSHA256: artifact.sha256, deadline: processDeadline,
            sendBytes: sendBytes, holdInputOpen: holdInputOpen,
            cancellation: cancellation, processEvent: processEvent)
        return (row, raw, identity)
    }
    errno = 0
    let closed = capturedFD >= 0 && fcntl(capturedFD, F_GETFD) == -1 && errno == EBADF
    return R1InspectionOutcome(job: job, receipt: raw, identity: identity, inputFDClosed: closed)
}

// One-way ownership handoff: run() is called once on its worker queue; result
// and port are read only after that queue posts completion to MainActor.
// Store access remains within ApplicationJobsB's serial withCurrentWaitingZIP.
// The only concurrently used object is the NSLock-backed cancellation token;
// worker evidence goes to the concrete locked ledger, never an arbitrary UI callback.
private final class R1InspectionWork: @unchecked Sendable {
    let owner: ApplicationJobsB, id: UUID, port: R1WorkerProcessPort, stop: R1WorkerCancellation
    let ledger: R1HumanOperationLedger?
    let operation: [String: Any]
    private(set) var result: Result<R1InspectionOutcome, Error>?
    init(owner: ApplicationJobsB, id: UUID, port: R1WorkerProcessPort, stop: R1WorkerCancellation,
         ledger: R1HumanOperationLedger?, operation: [String: Any]) {
        self.owner = owner; self.id = id; self.port = port; self.stop = stop
        self.ledger = ledger; self.operation = operation
    }
    func run() {
        result = Result { try r1InspectOwnedZIP(owner: owner, id: id, port: port,
            processDeadline: 5.0, sendBytes: nil, holdInputOpen: false, cancellation: stop,
            processEvent: { [ledger, operation] event in
                try ledger?.record("WORKER_PROCESS", ["operation": operation, "event": event])
            }) }
    }
}

@MainActor
final class R1ProductFlow {
    let owner: ApplicationJobsB
    private let portFactory: () -> R1WorkerProcessPort
    private let now: () -> Date
    private static let reviewWindowSeconds: TimeInterval = 300
    private let beforeInspection: (@MainActor () throws -> Void)?
    private(set) var currentJobID: UUID?
    private var selectedInputSHA256: String?
    private var attempted = Set<UUID>()
    private(set) var session: R1ReviewSession?
    private(set) var binding: R1ProductBinding?
    private(set) var lastReceiptData: Data?
    private(set) var issue: String?
    private(set) var workerStarts = 0
    private(set) var isInspecting = false
    private(set) var observationBusy = false
    private(set) var workerQuiescent = true
    private(set) var stopping = false
    private(set) var operationsHeld = false
    private var activeInspection: UUID?
    private var cancellation: R1WorkerCancellation?
    private var lastRecordedReview: String?
    var operationSource: R1ProductExecutionSource?
    var onOperationEvent: ((String, [String: Any]) throws -> Void)?
    var workerLedger: R1HumanOperationLedger?
    var onInspectionFinished: (() -> Void)?
    var onStopObservation: (() -> Void)?
    var canAcceptInput: Bool { !isInspecting && !observationBusy && workerQuiescent && !stopping && !operationsHeld }
    var canInspectCurrent: Bool {
        canAcceptInput && currentJobID.map { !attempted.contains($0) } == true && session == nil
    }

    init(owner: ApplicationJobsB, portFactory: @escaping () -> R1WorkerProcessPort,
         now: @escaping () -> Date = Date.init,
         beforeInspection: (@MainActor () throws -> Void)? = nil) {
        self.owner = owner; self.portFactory = portFactory; self.now = now
        self.beforeInspection = beforeInspection
    }

    // A11 offline extraction uses the same clock as the A3 review deadline.
    func currentReviewTime() -> Date { now() }

    func receive(_ batch: IngressBatchB7b) {
        // Preserve rejection diagnostics even while operation admission is held.
        do { try onOperationEvent?("INGRESS", r1OperationJSON(batch)) }
        catch { holdOperations("INGRESS_EVIDENCE_WRITE_FAILED"); return }
        guard canAcceptInput else { return }
        session = nil; binding = nil; lastReceiptData = nil; issue = nil; currentJobID = nil; selectedInputSHA256 = nil
        lastRecordedReview = nil
        guard batch.items.count == 1, let item = batch.items.first,
              item.disposition == "ACCEPTED_WAITING", let id = item.jobID else {
            issue = batch.items.count == 1 ? batch.items.first.map(r1VisibleIngressReason) ??
                "ZIPを受け付けられませんでした。" : "ZIPを受け付けられませんでした。"
            return
        }
        do { try selectCurrent(id) }
        catch { issue = "CURRENT_JOB_UNQUALIFIED" }
    }

    func selectCurrent(_ id: UUID) throws {
        guard canAcceptInput else { throw R1ProductFault.staleOrInterrupted }
        guard owner.store.productQualification else { throw R1ProductFault.staleOrInterrupted }
        let row = try owner.snapshot(id).job
        guard row.state == .waiting, row.workerScope == .notConnected,
              row.workerID == nil, row.resources == .none,
              !row.actualInspectionStarted, !row.actualInspectionCompleted,
              !row.authorityIssued, !row.aConnected,
              row.cleanup == "NONE", row.artifact != nil,
              row.intakeInputID != nil, row.intakeAttemptID != nil else {
            throw R1ProductFault.staleOrInterrupted
        }
        guard !attempted.contains(id) else { throw R1ProductFault.alreadyAttempted }
        currentJobID = id; session = nil; binding = nil; lastReceiptData = nil; issue = nil
        selectedInputSHA256 = row.artifact?.sha256
    }

    func inspectCurrent(processDeadline: Double = 5.0, reviewDeadline: Date? = nil,
                        sendBytes: Int64? = nil, holdInputOpen: Bool = false) throws {
        // Historical offline callers retain their synchronous API. The human
        // product always uses the cancellable async request below.
        guard operationSource == nil, canAcceptInput else { throw R1ProductFault.staleOrInterrupted }
        guard let id = currentJobID else { throw R1ProductFault.noCurrentJob }
        guard !attempted.contains(id) else { throw R1ProductFault.alreadyAttempted }
        attempted.insert(id) // A failed or ambiguous attempt is never auto-retried.
        let port = portFactory()
        defer { workerStarts += port.starts }
        do {
            try beforeInspection?()
            let outcome = try r1InspectOwnedZIP(owner: owner, id: id, port: port,
                processDeadline: processDeadline, sendBytes: sendBytes, holdInputOpen: holdInputOpen)
            try acceptReceipt(outcome, deadline: reviewDeadline, operation: nil)
        } catch {
            session = R1ReviewSession(receiptData: Data(), now: now(), deadline: reviewDeadline ?? now())
            binding = nil; lastReceiptData = nil
            issue = "INSPECTION_HOLD_\(error)"
            throw error
        }
    }

    func inspectCurrentAsync() throws {
        guard canInspectCurrent, let id = currentJobID else { throw R1ProductFault.noCurrentJob }
        attempted.insert(id)
        let attempt = UUID(), stop = R1WorkerCancellation()
        let port = portFactory()
        let operation = operationSource.map {
            R1ProductOperationIdentity(source: $0, registration: owner.store.registration, inspectionAttemptID: attempt)
        }
        do {
            try beforeInspection?()
            if let source = operationSource {
                guard onOperationEvent != nil, workerLedger != nil, source.sessionID == owner.store.sessionID,
                      operation?.matches(source: source, registration: owner.store.registration) == true else {
                    throw R1ProductFault.inputBinding
                }
            }
            try onOperationEvent?("INSPECTION_STARTED", ["jobID": id.uuidString,
                "operation": try operation.map(r1OperationJSON) ?? [:], "inspectionAttemptID": attempt.uuidString])
        } catch {
            holdOperations("INSPECTION_PREPARE_\(error)")
            throw error
        }
        let operationJSON = try operation.map(r1OperationJSON) ?? [:]
        activeInspection = attempt; cancellation = stop
        isInspecting = true; workerQuiescent = false; lastRecordedReview = nil
        let work = R1InspectionWork(owner: owner, id: id, port: port, stop: stop,
                                    ledger: workerLedger, operation: operationJSON)
        DispatchQueue(label: "Orchard.R1.CurrentInspection").async {
            work.run()
            DispatchQueue.main.async { [self] in
                defer { onInspectionFinished?() }
                workerStarts += work.port.starts
                workerQuiescent = work.port.resourcesQuiescent
                isInspecting = false; cancellation = nil
                guard activeInspection == attempt else { holdOperations("INSPECTION_ATTEMPT_CHANGED"); return }
                activeInspection = nil
                do {
                    guard let result = work.result else { throw R1ProductFault.workerContract }
                    let outcome = try result.get()
                    try onOperationEvent?("INSPECTION_RECEIPT", ["operation": operationJSON,
                        "receipt_sha256": hash54(outcome.receipt), "receipt_base64": outcome.receipt.base64EncodedString(),
                        "input_fd_closed": outcome.inputFDClosed, "worker_quiescent": workerQuiescent])
                    guard workerQuiescent, !stop.requested, !stopping else {
                        throw R1ProductFault.workerContract
                    }
                    try beforeInspection?()
                    try acceptReceipt(outcome, deadline: nil, operation: operation)
                    try onOperationEvent?("INSPECTION_BOUND", r1OperationJSON(snapshot()))
                } catch {
                    holdOperations("INSPECTION_HOLD_\(error)")
                    try? onOperationEvent?("INSPECTION_STOPPED", ["inspectionAttemptID": attempt.uuidString,
                        "reason": String(describing: error), "worker_quiescent": workerQuiescent,
                        "worker_resource_state": work.port.resourceReadback])
                }
            }
        }
    }

    private func acceptReceipt(_ outcome: R1InspectionOutcome, deadline: Date?,
                               operation: R1ProductOperationIdentity?) throws {
            let job = outcome.job, rawReceipt = outcome.receipt, fileIdentity = outcome.identity
            let inputFDClosed = outcome.inputFDClosed
            if let operation {
                guard let source = operationSource,
                      operation.matches(source: source, registration: owner.store.registration),
                      source.sessionID == owner.store.sessionID else { throw R1ProductFault.inputBinding }
            }
            guard currentJobID == job.jobID,
                  try owner.snapshot(job.jobID).job.revision == job.revision else { throw R1ProductFault.inputBinding }
            try owner.verifyArtifact(job)
            guard inputFDClosed, let artifact = job.artifact,
                  let inputID = job.intakeInputID, let attemptID = job.intakeAttemptID,
                  let receipt = try JSONSerialization.jsonObject(with: rawReceipt) as? [String: Any],
                  receipt["schema"] as? String == "orchard-r1-a2-child-outcome/1.0",
                  receipt["input_bytes_expected"] as? Int == Int(artifact.size),
                  receipt["parent_gate"] as? String == "HOLD",
                  receipt["authorizes_actions"] as? Bool == false else { throw R1ProductFault.workerContract }
            let reviewNow = now()
            let review = R1ReviewSession(receiptData: rawReceipt, now: reviewNow,
                deadline: deadline ?? reviewNow.addingTimeInterval(Self.reviewWindowSeconds))
            let visible = review.snapshot(now: now())
            if receipt["json_status"] as? String == "VALID" {
                guard visible.inspectionStatus != "UNKNOWN" || visible.decision == "HOLD",
                      let report = receipt["engine_report"] as? [String: Any],
                      let input = report["input"] as? [String: Any],
                      input["sha256"] as? String == artifact.sha256,
                      input["bytes"] as? Int == Int(artifact.size) else { throw R1ProductFault.workerContract }
            }
            session = review; lastReceiptData = rawReceipt
            binding = R1ProductBinding(ownerID: job.ownerID, storeID: job.storeID,
                sessionID: owner.store.sessionID, jobID: job.jobID, jobRevision: job.revision,
                intakeInputID: inputID, intakeAttemptID: attemptID, sourceKey: job.sourceKey,
                copiedZIPSize: artifact.size, copiedZIPSHA256: artifact.sha256,
                copiedZIPDevice: Int64(fileIdentity.device), copiedZIPInode: UInt64(fileIdentity.inode),
                copiedZIPUID: UInt32(fileIdentity.uid), workerReceiptSHA256: hash54(rawReceipt),
                workerPID: receipt["pid"] as? Int, workerJSONStatus: receipt["json_status"] as? String ?? "UNKNOWN",
                workerDirectReap: receipt["waitpid_reaped"] as? Bool == true,
                workerPipeFDsClosed: receipt["all_created_pipe_fds_closed"] as? Bool == true,
                inputFDClosedAfterReturn: inputFDClosed,
                displayedInputSHA256: artifact.sha256)
            binding?.operationIdentity = operation
            issue = visible.decision == "HOLD" ? "WORKER_OR_CONTENT_HOLD" : nil
    }

    func holdOperations(_ reason: String) {
        operationsHeld = true; issue = reason; binding = nil; session = nil
        cancellation?.request("SESSION_HOLD")
        onStopObservation?()
    }

    func requestStop(_ reason: String) {
        stopping = true; operationsHeld = true; issue = reason
        cancellation?.request(reason)
        onStopObservation?()
        do { try onOperationEvent?("STOP_REQUESTED", ["reason": reason, "inspection_active": isInspecting]) }
        catch { issue = "STOP_EVIDENCE_HOLD_\(error)" }
    }

    func beginObservation() throws {
        guard canAcceptInput else { throw R1ProductFault.staleOrInterrupted }
        observationBusy = true; workerQuiescent = false
    }

    func finishObservation(starts: Int, quiescent: Bool, passed: Bool) {
        observationBusy = false; workerStarts += starts; workerQuiescent = quiescent
        onStopObservation = nil
        if !passed || !quiescent { holdOperations("動作状態の確認を完了できませんでした。処理を停止しています。") }
        else { issue = "動作状態を記録しました。" }
    }

    func recordVisibleReview(origin: String) {
        guard let session, let binding else { return }
        let review = session.snapshot(now: now())
        let key = binding.workerReceiptSHA256 + ":" + review.decision
        guard key != lastRecordedReview else { return }
        do {
            try onOperationEvent?("REVIEW_DECISION", ["binding": try r1OperationJSON(binding),
                "decision": review.decision, "origin": origin])
            lastRecordedReview = key
        } catch { holdOperations("REVIEW_EVIDENCE_HOLD_\(error)") }
    }

    func snapshot() -> R1ProductState {
        let review = session?.snapshot(now: now())
        // UI refresh must not synchronously enter the store queue while that
        // queue is holding the worker's pinned-FD body.
        let inputSHA = binding?.copiedZIPSHA256 ?? selectedInputSHA256
        return R1ProductState(currentJobID: currentJobID, currentInputSHA256: inputSHA,
            workerStarts: workerStarts, reviewDecision: review?.decision ?? "HOLD",
            inspectionStatus: review?.inspectionStatus ?? "UNKNOWN",
            promptInjection: review?.promptInjection ?? "UNINSPECTABLE",
            confirmEnabled: review?.confirmEnabled ?? false,
            mockLabel: review?.mockOutput?.label, issue: issue, binding: binding)
    }
}
