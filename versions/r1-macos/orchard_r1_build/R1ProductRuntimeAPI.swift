// Typed connections only. Matching values do not attest an owner or grant GO.
import Foundation
import Darwin

struct R1ProductExecutionSource: Equatable {
    let commit: String?
    let tree: String?
    let appSourceManifestSHA256: String
    let productSourceSetSHA256: String
    let productCandidateManifestSHA256: String
    let workerInputPlanSHA256: String
    let recipeSHA256: String
    let materialID: UUID
    let buildAttemptID: UUID
    let sessionID: UUID

    func matches(worker: R1FreshWorkerBinding) -> Bool {
        commit == worker.sourceCommit && tree == worker.sourceTree &&
        appSourceManifestSHA256 == worker.appSourceManifestSHA256 &&
        productSourceSetSHA256 == worker.productSourceSetSHA256 &&
        productCandidateManifestSHA256 == worker.productCandidateManifestSHA256 &&
        workerInputPlanSHA256 == worker.workerInputPlanSHA256 &&
        recipeSHA256 == worker.recipeSHA256 && materialID == worker.materialID &&
        buildAttemptID == worker.buildAttemptID && sessionID == worker.sessionID
    }
}

// Runtime operation identity is created only after human startup has bound the
// fresh signed bundle and its v7 store. It does not authorize an app launch.
struct R1ProductOperationIdentity: Codable, Equatable {
    let ownerID: UUID, storeID: UUID, sessionID: UUID
    let buildAttemptID: UUID, materialID: UUID, inspectionAttemptID: UUID
    let appSourceManifestSHA256: String, productSourceSetSHA256: String
    let productCandidateManifestSHA256: String, workerInputPlanSHA256: String, recipeSHA256: String

    init(source: R1ProductExecutionSource, registration: RegistrationJobB, inspectionAttemptID: UUID) {
        ownerID = registration.ownerID; storeID = registration.storeID; sessionID = source.sessionID
        buildAttemptID = source.buildAttemptID; materialID = source.materialID
        self.inspectionAttemptID = inspectionAttemptID
        appSourceManifestSHA256 = source.appSourceManifestSHA256
        productSourceSetSHA256 = source.productSourceSetSHA256
        productCandidateManifestSHA256 = source.productCandidateManifestSHA256
        workerInputPlanSHA256 = source.workerInputPlanSHA256; recipeSHA256 = source.recipeSHA256
    }

    func matches(source: R1ProductExecutionSource, registration: RegistrationJobB) -> Bool {
        self == Self(source: source, registration: registration, inspectionAttemptID: inspectionAttemptID)
            && ![ownerID, storeID, sessionID, buildAttemptID, materialID].contains(inspectionAttemptID)
    }
}

func r1OperationJSON<T: Encodable>(_ value: T) throws -> [String: Any] {
    guard let result = try JSONSerialization.jsonObject(with: canonicalJobB(value)) as? [String: Any] else {
        throw R1FreshProductFault.configuration
    }
    return result
}

// The 2-2b resource is configuration data. Existing admission still owns GO.
struct R1AppSourceBinding: Decodable {
    let schema: String
    let appSourceManifestSHA256: String
    let productSourceSetSHA256: String
    let productCandidateManifestSHA256: String
    let recipeSHA256: String
    let workerInputPlanSHA256: String
    let bundleIdentifier: String
    let buildAttemptID: String
    let materialID: String
    let qualifiedExecutionCommit: String?
    let qualifiedExecutionTree: String?
    let liveSession: String
    let authorizesActions: Bool

    enum CodingKeys: String, CodingKey {
        case schema
        case appSourceManifestSHA256 = "app_source_manifest_sha256"
        case productSourceSetSHA256 = "product_source_set_sha256"
        case productCandidateManifestSHA256 = "product_candidate_manifest_sha256"
        case recipeSHA256 = "recipe_sha256"
        case workerInputPlanSHA256 = "worker_input_plan_sha256"
        case bundleIdentifier = "bundle_identifier"
        case buildAttemptID = "build_attempt_id"
        case materialID = "material_id"
        case qualifiedExecutionCommit = "qualified_execution_commit"
        case qualifiedExecutionTree = "qualified_execution_tree"
        case liveSession = "live_session"
        case authorizesActions = "authorizes_actions"
    }

    static func hex(_ value: String, _ length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    private func identifier(_ value: String) throws -> UUID {
        guard Self.hex(value, 32), value != String(repeating: "0", count: 32) else {
            throw R1FreshProductFault.configuration
        }
        let chars = Array(value)
        let text = String(chars[0..<8]) + "-" + String(chars[8..<12]) + "-" +
            String(chars[12..<16]) + "-" + String(chars[16..<20]) + "-" + String(chars[20..<32])
        guard let result = UUID(uuidString: text) else { throw R1FreshProductFault.configuration }
        return result
    }

    func executionSource(sessionID: UUID) throws -> R1ProductExecutionSource {
        let hashes = [appSourceManifestSHA256, productSourceSetSHA256,
                      productCandidateManifestSHA256, recipeSHA256, workerInputPlanSHA256]
        let gitPair = (qualifiedExecutionCommit == nil && qualifiedExecutionTree == nil) ||
            (qualifiedExecutionCommit.map { Self.hex($0, 40) } == true &&
             qualifiedExecutionTree.map { Self.hex($0, 40) } == true)
        guard schema == "orchard-fresh-app-source-binding/1", hashes.allSatisfy({ Self.hex($0, 64) }),
              gitPair, !authorizesActions,
              liveSession == "REQUIRES_SEPARATE_CURRENT_NATIVE_ADMISSION",
              bundleIdentifier == "com.orchard.release1.a" + buildAttemptID else {
            throw R1FreshProductFault.configuration
        }
        let material = try identifier(materialID), attempt = try identifier(buildAttemptID)
        guard material != attempt, material != sessionID, attempt != sessionID else {
            throw R1FreshProductFault.configuration
        }
        return R1ProductExecutionSource(commit: qualifiedExecutionCommit, tree: qualifiedExecutionTree,
            appSourceManifestSHA256: appSourceManifestSHA256, productSourceSetSHA256: productSourceSetSHA256,
            productCandidateManifestSHA256: productCandidateManifestSHA256, workerInputPlanSHA256: workerInputPlanSHA256,
            recipeSHA256: recipeSHA256, materialID: material, buildAttemptID: attempt, sessionID: sessionID)
    }

    func workerBinding(signedSHA256: String, bytes: Int64, sessionID: UUID) throws -> R1FreshWorkerBinding {
        let source = try executionSource(sessionID: sessionID)
        let worker = R1FreshWorkerBinding(signedExecutableSHA256: signedSHA256, executableBytes: bytes,
            sourceCommit: source.commit, sourceTree: source.tree,
            appSourceManifestSHA256: source.appSourceManifestSHA256, productSourceSetSHA256: source.productSourceSetSHA256,
            productCandidateManifestSHA256: source.productCandidateManifestSHA256, workerInputPlanSHA256: source.workerInputPlanSHA256,
            recipeSHA256: source.recipeSHA256, materialID: source.materialID,
            buildAttemptID: source.buildAttemptID, sessionID: sessionID)
        try worker.validateFields(sessionID: sessionID)
        return worker
    }

    func launchConfiguration(rootURL: URL, waitingURL: URL, extractionRootURL: URL,
                             registration: RegistrationJobB, sessionID: UUID, appBundle: URL,
                             signedWorkerSHA256: String, workerBytes: Int64) throws -> R1ProductLaunchConfiguration {
        let configuration = R1ProductLaunchConfiguration(rootURL: rootURL, waitingURL: waitingURL,
            extractionRootURL: extractionRootURL, registration: registration, sessionID: sessionID,
            appBundle: appBundle, executionSource: try executionSource(sessionID: sessionID),
            worker: try workerBinding(signedSHA256: signedWorkerSHA256, bytes: workerBytes, sessionID: sessionID))
        try configuration.validateLayout()
        return configuration
    }

    static func read(in bundle: URL) throws -> R1AppSourceBinding {
        let path = bundle.appendingPathComponent("Contents/Resources/OrchardProduct/SourceBinding.json")
        return try JSONDecoder().decode(Self.self, from: readJobFileB(path, cap: 65_536))
    }

    func verify(configuration: R1ProductLaunchConfiguration) throws {
        let source = try executionSource(sessionID: configuration.sessionID)
        guard bundleIdentifier == Bundle.main.bundleIdentifier,
              source == configuration.executionSource, source.matches(worker: configuration.worker) else {
            throw R1FreshProductFault.configuration
        }
    }
}

// A bundle object observed after fresh admission. This is file identity, not
// execution-principal identity. Actual spawn/OS acceptance remains separate.
struct R1RuntimeFileIdentity: Equatable {
    let device: Int64, inode: UInt64, uid: UInt32, mode: UInt32, links: UInt64, bytes: Int64
    let modifiedSec: Int64, modifiedNsec: Int64, changedSec: Int64, changedNsec: Int64
    init(_ value: stat) {
        device = Int64(value.st_dev); inode = UInt64(value.st_ino)
        uid = UInt32(value.st_uid); mode = UInt32(value.st_mode)
        links = UInt64(value.st_nlink); bytes = Int64(value.st_size)
        modifiedSec = Int64(value.st_mtimespec.tv_sec); modifiedNsec = Int64(value.st_mtimespec.tv_nsec)
        changedSec = Int64(value.st_ctimespec.tv_sec); changedNsec = Int64(value.st_ctimespec.tv_nsec)
    }
    func verifyCurrent(_ path: URL) throws {
        var value = stat()
        guard path.resolvingSymlinksInPath().path == path.path,
              lstat(path.path, &value) == 0, value.st_mode & S_IFMT == S_IFREG,
              value.st_nlink == 1, R1RuntimeFileIdentity(value) == self else {
            throw R1FreshProductFault.worker
        }
    }
}

struct R1ProductReviewKey: Equatable {
    let ownerID: UUID, storeID: UUID, sessionID: UUID, jobID: UUID
    let jobRevision: Int
    let intakeInputID: UUID, intakeAttemptID: UUID
    let inputSHA256: String, workerReceiptSHA256: String
    let operationIdentity: R1ProductOperationIdentity?
    init(_ binding: R1ProductBinding) {
        ownerID = binding.ownerID; storeID = binding.storeID; sessionID = binding.sessionID
        jobID = binding.jobID; jobRevision = binding.jobRevision
        intakeInputID = binding.intakeInputID; intakeAttemptID = binding.intakeAttemptID
        inputSHA256 = binding.copiedZIPSHA256; workerReceiptSHA256 = binding.workerReceiptSHA256
        operationIdentity = binding.operationIdentity
    }
}

struct R1ProductExtractionOutput {
    let review: R1ProductReviewKey
    let ready: R1A12Ready
    init(binding: R1ProductBinding, ready: R1A12Ready, attemptID: UUID, root: URL) throws {
        guard ready.attemptID == attemptID, ready.root == root.path,
              ready.folder == root.appendingPathComponent(R1A12Transaction.folderName(attemptID)).path else {
            throw R1FreshProductFault.confirmation
        }
        review = R1ProductReviewKey(binding); self.ready = ready
    }
    func matches(binding: R1ProductBinding?, currentJobID: UUID?) -> Bool {
        guard let binding, currentJobID == review.jobID else { return false }
        return review == R1ProductReviewKey(binding)
    }
}

enum R1ProductExtractionPhase: String { case awaiting = "AWAITING_REVIEW", pending = "PENDING", ready = "READY", held = "HOLD" }

struct R1ProductRuntimeSnapshot {
    let inspection: R1ProductState
    let extractionPhase: R1ProductExtractionPhase
    let extractionAttemptID: UUID?
    let output: R1ProductExtractionOutput?
    let aiHandoffPerformed = false
    let authorizesActions = false
}
