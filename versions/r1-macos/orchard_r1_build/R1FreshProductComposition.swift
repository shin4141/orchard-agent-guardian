// B/C composition adapter. A1/A3/A9/A11/A12 algorithms stay in their receivers.
import AppKit
import Foundation
import Darwin

enum R1FreshProductFault: String, Error { case admission, configuration, worker, confirmation }

struct R1FreshWorkerBinding {
    let signedExecutableSHA256: String
    let executableBytes: Int64
    let sourceCommit: String?
    let sourceTree: String?
    let appSourceManifestSHA256: String
    let productSourceSetSHA256: String
    let productCandidateManifestSHA256: String
    let workerInputPlanSHA256: String
    let recipeSHA256: String
    let materialID: UUID
    let buildAttemptID: UUID
    let sessionID: UUID

    func validateFields(sessionID: UUID) throws {
        func hex(_ value: String, _ length: Int) -> Bool {
            value.utf8.count == length && value.utf8.allSatisfy {
                (48...57).contains($0) || (97...102).contains($0)
            }
        }
        let gitPair = (sourceCommit == nil && sourceTree == nil) ||
            (sourceCommit.map { hex($0, 40) } == true && sourceTree.map { hex($0, 40) } == true)
        let sourceHashes = [appSourceManifestSHA256, productSourceSetSHA256,
                            productCandidateManifestSHA256, workerInputPlanSHA256]
        guard hex(signedExecutableSHA256, 64), gitPair, sourceHashes.allSatisfy({ hex($0, 64) }),
              hex(recipeSHA256, 64), executableBytes > 0, executableBytes <= 67_108_864,
              signedExecutableSHA256 != R1WorkerRuntime.a8WorkerSHA256,
              self.sessionID == sessionID, materialID != buildAttemptID,
              materialID != sessionID, buildAttemptID != sessionID else {
            throw R1FreshProductFault.worker
        }
    }
}

struct R1ProductLaunchConfiguration {
    let rootURL: URL
    let waitingURL: URL
    let extractionRootURL: URL
    let registration: RegistrationJobB
    let sessionID: UUID
    let appBundle: URL
    let executionSource: R1ProductExecutionSource
    let worker: R1FreshWorkerBinding

    func validateLayout() throws {
        let directories = [rootURL, waitingURL, extractionRootURL, appBundle]
        guard directories.allSatisfy({ url in
            url.isFileURL && url.path.hasPrefix("/") && !url.path.utf8.contains(0) &&
            url.standardizedFileURL.path == url.path &&
            url.resolvingSymlinksInPath().path == url.path
        }), appBundle.path == Bundle.main.bundleURL.path else {
            throw R1FreshProductFault.configuration
        }
        let storage = [rootURL.path, waitingURL.path, extractionRootURL.path]
        for i in storage.indices {
            for j in storage.indices where i != j {
                guard storage[i] != storage[j], !storage[i].hasPrefix(storage[j] + "/") else {
                    throw R1FreshProductFault.configuration
                }
            }
            guard !storage[i].hasPrefix(appBundle.path + "/"), storage[i] != appBundle.path,
                  !appBundle.path.hasPrefix(storage[i] + "/") else {
                throw R1FreshProductFault.configuration
            }
        }
        try worker.validateFields(sessionID: sessionID)
        guard executionSource.matches(worker: worker) else { throw R1FreshProductFault.worker }
    }

    func validateManifest() throws {
        try R1AppSourceBinding.read(in: appBundle).verify(configuration: self)
    }
}

// A real provider must bind live owner, immutable source, fresh signed bundle,
// worker, private storage and current session. Configuration values are not
// attestation. Historical admissions do not conform to these interfaces.
@MainActor
protocol R1FreshProductAdmission: R1A11NativeExtractionAdmission {
    func verifyFreshLaunch(configuration: R1ProductLaunchConfiguration) throws
    func admitCurrentZIP(_ original: URL, sessionID: UUID) throws -> URL?
}

@MainActor
protocol R1ProductLaunchProviding {
    func load() throws -> (configuration: R1ProductLaunchConfiguration, admission: R1FreshProductAdmission)
}

@MainActor
struct HoldR1ProductLaunchProvider: R1ProductLaunchProviding {
    func load() throws -> (configuration: R1ProductLaunchConfiguration, admission: R1FreshProductAdmission) {
        throw R1FreshProductFault.admission
    }
}

// Adapts the existing provider and v7 registration; it issues no authority and
// creates no store, container, receipt or alternate worker path.
@MainActor
struct R1ManifestProductLaunchProvider: R1ProductLaunchProviding {
    let upstream: R1ProductLaunchProviding
    func load() throws -> (configuration: R1ProductLaunchConfiguration, admission: R1FreshProductAdmission) {
        let (configuration, admission) = try upstream.load()
        try admission.verifyCurrentNativeScope()
        try admission.verifyR1ProductScope()
        try admission.verifyFreshLaunch(configuration: configuration)
        try configuration.validateLayout()
        try configuration.validateManifest()
        try R1ProductAppEntry.validateV7Registration(rootURL: configuration.rootURL,
                                                    registration: configuration.registration)
        return (configuration, admission)
    }
}

extension R1WorkerRuntime {
    static func freshBundled(in app: URL, binding: R1FreshWorkerBinding,
                             sessionID: UUID, revalidate: @escaping () throws -> Void) throws -> R1WorkerRuntime {
        try binding.validateFields(sessionID: sessionID)
        let contents = app.appendingPathComponent("Contents", isDirectory: true)
        let worker = contents.appendingPathComponent("MacOS/OrchardZipWorker")
        let engine = contents.appendingPathComponent("Resources/OrchardZipWorker/engine/zip_inspector.py")
        var value = stat()
        guard worker.resolvingSymlinksInPath().path == worker.path,
              engine.resolvingSymlinksInPath().path == engine.path,
              lstat(worker.path, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
              value.st_nlink == 1, value.st_size == binding.executableBytes else {
            throw R1FreshProductFault.worker
        }
        let workerIdentity = R1RuntimeFileIdentity(value)
        var engineValue = stat()
        guard lstat(engine.path, &engineValue) == 0, engineValue.st_mode & S_IFMT == S_IFREG,
              engineValue.st_nlink == 1, engineValue.st_size == 18_036 else { throw R1FreshProductFault.worker }
        let engineIdentity = R1RuntimeFileIdentity(engineValue)
        let runtime = R1WorkerRuntime(executable: worker,
            argvTail: ["-P", "-S", "-B", engine.path, "--fd", "0"],
            environment: ["PATH": "/usr/bin:/bin", "LC_ALL": "C",
                "PYTHONHOME": contents.appendingPathComponent("Resources/OrchardZipWorker").path,
                "PYTHONPATH": contents.appendingPathComponent("Frameworks").path],
            engine: engine, expectedExecutableSHA256: binding.signedExecutableSHA256,
            label: "FRESH_SIGNED_WORKER_REQUIRES_EXACT_ADMISSION",
            validateFreshAtUse: {
                try revalidate()
                try workerIdentity.verifyCurrent(worker)
                try engineIdentity.verifyCurrent(engine)
            })
        // A9 repeats file identity before/after SHA reads, before pipes/spawn.
        // Fresh owner admission runs on MainActor immediately before the job FD.
        try runtime.validateBeforeSpawn()
        return runtime
    }
}

@MainActor
final class R1FreshProductSession {
    let entry: R1ProductAppEntry
    let extraction: R1LimitedExtractionControl
    var humanOperations: R1HumanOperationSession?

    private init(entry: R1ProductAppEntry, extraction: R1LimitedExtractionControl) {
        self.entry = entry; self.extraction = extraction
    }

    static func prepare(using provider: R1ProductLaunchProviding) throws -> R1FreshProductSession {
        let (configuration, admission) = try provider.load()
        return try prepare(configuration: configuration, admission: admission)
    }

    // The human product supplies its already-observed running code and fresh
    // operation store directly. It does not construct or load a launch provider.
    static func prepare(configuration: R1ProductLaunchConfiguration, admission: R1FreshProductAdmission,
                        runtimeRevalidate: (() throws -> Void)? = nil) throws -> R1FreshProductSession {
        try admission.verifyCurrentNativeScope()
        try admission.verifyR1ProductScope()
        try admission.verifyFreshLaunch(configuration: configuration)
        try configuration.validateLayout()
        let runtime = try R1WorkerRuntime.freshBundled(in: configuration.appBundle,
            binding: configuration.worker, sessionID: configuration.sessionID, revalidate: {
                try configuration.validateLayout()
                try configuration.validateManifest()
                try runtimeRevalidate?()
            })
        let entry = try R1ProductAppEntry.prepare(rootURL: configuration.rootURL,
            waitingURL: configuration.waitingURL, registration: configuration.registration,
            sessionID: configuration.sessionID, appBundle: configuration.appBundle,
            admission: admission, runtime: runtime, beforeInspection: {
                try admission.verifyCurrentNativeScope()
                try admission.verifyR1ProductScope()
                try admission.verifyFreshLaunch(configuration: configuration)
                try configuration.validateLayout()
                try configuration.validateManifest()
            })
        entry.composition.root.nativeInputAdmission = { original in
            do { try admission.verifyFreshLaunch(configuration: configuration) }
            catch let rejection as NativeInputRejectionB7b { throw rejection }
            catch { throw NativeInputRejectionB7b(stage: .freshScope, code: .freshScopeRejected) }
            do { try configuration.validateManifest() }
            catch { throw NativeInputRejectionB7b(stage: .manifest, code: .manifestRejected) }
            return try admission.admitCurrentZIP(original, sessionID: configuration.sessionID)
        }
        let extraction = R1LimitedExtractionControl(entry: entry, configuration: configuration,
                                                     admission: admission)
        entry.window.delegate = entry.composition.root.windowDelegate
        return R1FreshProductSession(entry: entry, extraction: extraction)
    }

    func snapshot() -> R1ProductRuntimeSnapshot {
        extraction.refresh()
        return R1ProductRuntimeSnapshot(inspection: entry.composition.flow.snapshot(),
            extractionPhase: extraction.phase, extractionAttemptID: extraction.lastAttemptID,
            output: extraction.outputForCurrentReview())
    }
}

// A second explicit human action consumes only the current confirmed job.
// No automatic extraction, retry, restart promotion, cleanup or AI handoff.
@MainActor
final class R1LimitedExtractionControl: NSObject {
    private let entry: R1ProductAppEntry
    private let configuration: R1ProductLaunchConfiguration
    private let admission: R1FreshProductAdmission
    private let extractor = R1A11OfflineExtractor()
    private var attempted = Set<UUID>()
    private let button = NSButton(title: "確認したZIPを限定展開", target: nil, action: nil)
    private let status = NSTextField(wrappingLabelWithString: "検査結果を確認した後、限定展開を選択してください。")
    private(set) var lastAttemptID: UUID?
    private var ready: R1A12Ready?
    private var displayedReview: R1ProductReviewKey?
    private var output: R1ProductExtractionOutput?
    private(set) var phase: R1ProductExtractionPhase = .awaiting
    private(set) var allAttemptIDs = [UUID]()
    private var shuttingDown = false
    var operationReady: (() -> Bool)?
    var operationEvent: ((String, [String: Any]) throws -> Void)?

    init(entry: R1ProductAppEntry, configuration: R1ProductLaunchConfiguration,
         admission: R1FreshProductAdmission) {
        self.entry = entry; self.configuration = configuration; self.admission = admission
        super.init()
        button.identifier = NSUserInterfaceItemIdentifier("r1.product.extract-confirmed")
        button.target = self; button.action = #selector(extractAction(_:))
        status.isSelectable = false
        entry.composition.screen.installExtractionControls(button: button, status: status)
        entry.composition.screen.onStateChanged = { [weak self] in self?.refresh() }
        refresh()
    }

    func refresh() {
        let flow = entry.composition.flow
        let currentReview = flow.binding.map { R1ProductReviewKey($0) }
        if displayedReview != currentReview {
            displayedReview = currentReview
            ready = nil; output = nil; lastAttemptID = nil; phase = .awaiting
            status.stringValue = "検査結果を確認した後、限定展開を選択してください。"
        }
        let decision = flow.session?.snapshot(now: flow.currentReviewTime()).decision
        button.isEnabled = !shuttingDown && !flow.isInspecting && flow.workerQuiescent &&
            !flow.stopping && !flow.operationsHeld && (operationReady?() ?? true) &&
            decision == R1ReviewDecision.confirmed.rawValue &&
            flow.currentJobID.map { !attempted.contains($0) } == true
        // The A3 session still records confirmation only; this label gives it
        // no extraction authority. The separate button/admission is mandatory.
        entry.composition.screen.reviewPanel?.confirmButton.title = "検査結果を確認"
    }

    func outputForCurrentReview() -> R1ProductExtractionOutput? {
        guard let output, phase == .ready,
              output.matches(binding: entry.composition.flow.binding,
                             currentJobID: entry.composition.flow.currentJobID) else { return nil }
        return output
    }

    @objc private func extractAction(_ sender: NSButton) {
        refresh()
        let flow = entry.composition.flow
        guard button.isEnabled, let jobID = flow.currentJobID else { return }
        attempted.insert(jobID)
        let attemptID = UUID()
        allAttemptIDs.append(attemptID)
        lastAttemptID = attemptID; ready = nil; output = nil; phase = .pending
        defer { refresh() }
        do {
            try operationEvent?("EXTRACTION_ACTION", ["attempt_id": attemptID.uuidString,
                "binding": try flow.binding.map(r1OperationJSON) ?? [:], "origin": "APPKIT_SEPARATE_CONTROL_ACTION"])
            try admission.verifyFreshLaunch(configuration: configuration)
            let prepared = try extractor.prepareNative(flow: flow,
                actorID: configuration.registration.ownerID, sessionID: configuration.sessionID,
                attemptID: attemptID, destinationRoot: configuration.extractionRootURL,
                admission: admission)
            try admission.verifyFreshLaunch(configuration: configuration)
            try admission.verifyLimitedExtraction(binding: prepared.binding, attemptID: attemptID,
                                                   destinationRoot: configuration.extractionRootURL)
            guard flow.currentJobID == prepared.binding.jobID,
                  flow.session?.snapshot(now: flow.currentReviewTime()).decision ==
                    R1ReviewDecision.confirmed.rawValue else { throw R1FreshProductFault.confirmation }
            let result = try R1A12Transaction.write(prepared: prepared,
                root: configuration.extractionRootURL, attemptID: attemptID)
            let boundOutput = try R1ProductExtractionOutput(binding: prepared.binding, ready: result,
                attemptID: attemptID, root: configuration.extractionRootURL)
            guard boundOutput.matches(binding: flow.binding, currentJobID: flow.currentJobID) else {
                throw R1FreshProductFault.confirmation
            }
            ready = result
            output = boundOutput; phase = .ready
            try operationEvent?("EXTRACTION_READY", ["attempt_id": attemptID.uuidString,
                "ready": try r1OperationJSON(result), "binding": try r1OperationJSON(prepared.binding)])
            status.stringValue = "限定展開を読み戻しました。AI引き渡しは未実施です。"
        } catch {
            ready = nil; output = nil; phase = .held
            status.stringValue = "限定展開はHOLDです。自動再試行せず、このattemptの記録を保持します。"
            try? operationEvent?("EXTRACTION_HOLD", ["attempt_id": attemptID.uuidString,
                "reason": String(describing: error), "automatic_retry": false])
            entry.composition.flow.holdOperations("EXTRACTION_HOLD_\(error)")
        }
    }

    func requestShutdown() {
        shuttingDown = true
        refresh()
    }
}
