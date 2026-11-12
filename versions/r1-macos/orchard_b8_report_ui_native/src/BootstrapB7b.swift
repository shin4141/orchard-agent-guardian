// Composition only: B7a copy/hash/metadata/store implementations remain unchanged.
import Foundation
import AppKit

enum BootstrapFaultB7b: String, Error {
    case missingNativeExecutionQualification, wrongEvidenceDriver, context, duplicateBootstrap, ownerStillOpen
}
enum IngressOriginB7b: String, Codable { case appKitImplicit, syntheticCallback }
// Only closed vocabulary and numeric errno cross the input-admission boundary.
// Do not attach an input URL, filename, exception description or file contents.
struct NativeInputRejectionB7b: Error, Codable {
    enum Stage: String, Codable { case provider, freshScope, manifest, session, url, alias, selectedFile, physicalFile, closure }
    enum Code: String, Codable {
        case providerNotReady, providerDeclined, unexpectedProviderFailure
        case freshScopeRejected, manifestRejected, admissionScopeRejected
        case inactiveSession, sessionMismatch, ownerEvidenceRejected, runningCodeRejected
        case layoutRejected, registrationRejected, operationSourceMismatch, freshBindingMismatch
        case flowUnavailable, flowNotReady
        case nonFileURL, remoteHost, credentialsOrPort, query, fragment, nonZIP
        case invalidAbsolutePath, dotComponent, emptyComponent
        case aliasLookupFailed, aliasNotTrusted, aliasTargetMismatch, aliasChanged, aliasDisallowed
        case selectedLookupFailed, nonRegularFile, multipleLinks, symlinkDisallowed
        case routeOpenFailed, routeStatFailed, selectedIdentityMismatch
        case realpathFailed, physicalLocationDisallowed, physicalOpenFailed, physicalStatFailed, physicalIdentityMismatch
        case finalLookupFailed, finalStatFailed, fileChanged, descriptorCloseFailed
    }
    let stage: Stage
    let code: Code
    var systemErrno: Int32? = nil
    // At most the three locally owned descriptors; no close is retried.
    var cleanupErrnos: [Int32]? = nil
}
struct IngressItemB7b: Codable {
    var inputIndex: Int; var jobID: UUID?; var disposition: String; var reason: String
    var accessEvidence: String; var began: Bool; var ended: Bool; var jobAdmissionAttempted: Bool
    var nativeSandboxQualification = "UNKNOWN_NOT_TESTED"
    var nativeInputRejection: NativeInputRejectionB7b? = nil
}
struct IngressBatchB7b: Codable {
    var deliveryID = UUID()
    var origin: IngressOriginB7b
    var items: [IngressItemB7b]
    var actualInspectionStarted = false
    var actualInspectionCompleted = false
    var safety = "UNKNOWN_NOT_INSPECTED"
    var authorityIssued = false
}

// Apple documents implicit start for original URLs delivered by an open panel or Dock drop.
// Adoption records lifecycle ownership, not proof of entitlement, signing, or successful I/O.
// Explicit bookmark access retains the separate SecurityScopedURLLeaseB implementation.
final class AppKitImplicitLeaseB7b: AccessLeaseB {
    private var original: URL?
    private var consumed = false
    private(set) var active = false
    func begin(_ url: URL) -> Bool {
        guard !consumed, original == nil, url.isFileURL else { return false }
        consumed = true; original = url; active = true
        return true
    }
    func end() {
        if let original { original.stopAccessingSecurityScopedResource() }
        original = nil; active = false
    }
    deinit { end() }
}
final class BorrowedCallbackLeaseB7b: AccessLeaseB {
    let owner: AccessLeaseB
    let original: URL
    private var borrowed = false
    private var ended = false
    var active: Bool { borrowed && !ended && owner.active }
    init(owner: AccessLeaseB, original: URL) { self.owner = owner; self.original = original }
    func begin(_ url: URL) -> Bool {
        guard !borrowed, !ended, owner.active, url == original else { return false }
        borrowed = true; return true
    }
    func end() { borrowed = false; ended = true }
}
final class NoCallbackLeaseB7b: AccessLeaseB {
    var active: Bool { false }
    func begin(_ url: URL) -> Bool { false }
    func end() {}
}
final class CallbackContextB7b {
    var current: (AccessLeaseB, URL)?
    let metadata: MetadataProbeB
    let maxBytes: Int64
    var configureReceiver: (ZipDropReceiverB) -> Void = { _ in }
    init(metadata: MetadataProbeB, maxBytes: Int64 = ZipDropReceiverB.syntheticCap) {
        self.metadata = metadata; self.maxBytes = maxBytes
    }
    func receiver(_ waiting: URL) -> ZipDropReceiverB {
        let lease: AccessLeaseB
        if let (scope, url) = current { lease = BorrowedCallbackLeaseB7b(owner: scope, original: url) }
        else { lease = NoCallbackLeaseB7b() }
        let receiver = ZipDropReceiverB(pendingParent: waiting, metadata: metadata,
                                        leaseFactory: { lease }, maxBytes: maxBytes)
        configureReceiver(receiver); return receiver
    }
}

// Separate native-execution admission interface; this source issues no Authority.
protocol NativeExecutionAdmissionB7b { func verifyCurrentNativeScope() throws }
struct HoldNativeExecutionB7b: NativeExecutionAdmissionB7b {
    func verifyCurrentNativeScope() throws { throw BootstrapFaultB7b.missingNativeExecutionQualification }
}

@MainActor
final class MacAppBootstrapB7b {
    enum Driver: Equatable { case offlineSynthetic, offlineProductQualification, nativeCandidate }
    let driver: Driver
    let applicationOwner: ApplicationJobsB
    let context: CallbackContextB7b
    let projection: WindowProjectionJobsB
    let windowDelegate: WindowLifecycleJobsB
    let applicationDelegate: ApplicationLifecycleJobsB
    private let accessFactory: () -> AccessLeaseB
    private let publish: (ApplicationViewJobsB) -> Void
    private var routing = false
    private(set) var lastIngress: IngressBatchB7b?
    private(set) var admissionAttempts = 0
    var onIngress: ((IngressBatchB7b) -> Void)?
    // An exact native test may narrow one callback URL to an already verified
    // canonical file URL. Existing callers without this hook keep their route.
    var nativeInputAdmission: ((URL) throws -> URL?)?

    private init(store: PersistentJobsB, driver: Driver, metadata: MetadataProbeB,
                 accessFactory: @escaping () -> AccessLeaseB, publish: @escaping (ApplicationViewJobsB) -> Void,
                 present: @escaping ([JobSnapshotB]) -> Void) throws {
        self.driver = driver; self.accessFactory = accessFactory; self.publish = publish
        let context = CallbackContextB7b(metadata: metadata, maxBytes: store.maxIntakeBytes); self.context = context
        let owner = try ApplicationJobsB(store: store, receiverFactory: { context.receiver($0) }); applicationOwner = owner
        let projection = WindowProjectionJobsB(applicationOwner: owner); self.projection = projection
        windowDelegate = WindowLifecycleJobsB(projection: projection)
        let bridge = IngressBridgeB7b()
        let dock = DockZipDelegateB(route: { bridge.receive($0, $1) })
        applicationDelegate = ApplicationLifecycleJobsB(applicationOwner: owner, dock: dock, projection: projection,
            publish: publish, requestPresentation: present)
        bridge.root = self
    }
    static func offlineSynthetic(store: PersistentJobsB, metadata: MetadataProbeB,
        accessFactory: @escaping () -> AccessLeaseB, publish: @escaping (ApplicationViewJobsB) -> Void = { _ in },
        present: @escaping ([JobSnapshotB]) -> Void = { _ in }) throws -> MacAppBootstrapB7b {
        try MacAppBootstrapB7b(store: store, driver: .offlineSynthetic, metadata: metadata,
            accessFactory: accessFactory, publish: publish, present: present)
    }
    static func offlineProductQualification(store: PersistentJobsB, metadata: MetadataProbeB,
        accessFactory: @escaping () -> AccessLeaseB, publish: @escaping (ApplicationViewJobsB) -> Void = { _ in },
        present: @escaping ([JobSnapshotB]) -> Void = { _ in }) throws -> MacAppBootstrapB7b {
        guard store.productOfflineQualification else { throw BootstrapFaultB7b.wrongEvidenceDriver }
        return try MacAppBootstrapB7b(store: store, driver: .offlineProductQualification, metadata: metadata,
            accessFactory: accessFactory, publish: publish, present: present)
    }
    static func nativeCandidate(root: URL, waiting: URL, registration: RegistrationJobB,
        sessionID: UUID? = nil,
        admission: NativeExecutionAdmissionB7b = HoldNativeExecutionB7b(),
        publish: @escaping (ApplicationViewJobsB) -> Void, present: @escaping ([JobSnapshotB]) -> Void) throws -> MacAppBootstrapB7b {
        try admission.verifyCurrentNativeScope()
        let store = try PersistentJobsB(root: root, waiting: waiting, registration: registration,
                                        sessionID: sessionID)
        return try MacAppBootstrapB7b(store: store, driver: .nativeCandidate, metadata: FoundationMetadataProbeB(),
            accessFactory: { AppKitImplicitLeaseB7b() }, publish: publish, present: present)
    }
    func bindNativeCallbacks(to app: NSApplication, admission: NativeExecutionAdmissionB7b = HoldNativeExecutionB7b()) throws {
        guard driver == .nativeCandidate else { throw BootstrapFaultB7b.wrongEvidenceDriver }
        try admission.verifyCurrentNativeScope()
        try ProcessBootstrapOwnerB7b.retain(self)
        app.delegate = applicationDelegate
    }
    fileprivate func receive(_ urls: [URL], origin: IngressOriginB7b) -> IngressBatchB7b {
        func finish(_ items: [IngressItemB7b]) -> IngressBatchB7b {
            let result = IngressBatchB7b(origin: origin, items: items)
            lastIngress = result; publish(applicationOwner.viewState()); onIngress?(result)
            return result
        }
        let expected: IngressOriginB7b = driver == .offlineSynthetic ? .syntheticCallback : .appKitImplicit
        guard origin == expected else {
            return finish(urls.indices.map {
                IngressItemB7b(inputIndex: $0, disposition: "HOLD", reason: "WRONG_DRIVER_NO_NATIVE_QUALIFICATION", accessEvidence: "NONE", began: false, ended: false, jobAdmissionAttempted: false)
            })
        }
        let reentrant = routing
        if !reentrant { routing = true }
        defer { if !reentrant { routing = false } }
        var items = [IngressItemB7b]()
        for (index, original) in urls.enumerated() {
            let scope = accessFactory()
            let evidence = driver == .offlineSynthetic ? "SIMULATED_ACCESS_NOT_NATIVE_PERMISSION" : "DOCUMENTED_APPKIT_IMPLICIT_SCOPE_ACTUAL_ACCESS_UNQUALIFIED"
            let began = scope.begin(original)
            var item = IngressItemB7b(inputIndex: index, disposition: "HOLD", reason: "ACCESS_NOT_CONFIRMED", accessEvidence: evidence, began: began, ended: false, jobAdmissionAttempted: false)
            if began {
                if reentrant { item.reason = "REENTRANT_CALLBACK_NO_ADMISSION" }
                else if !original.isFileURL { item.reason = "NON_FILE_URL" }
                else if original.pathExtension.lowercased() != "zip" { item.reason = "ZIP_ROUTE_ONLY_NOT_FORMAT_PROOF" }
                else if applicationOwner.store.isClosed { item.reason = "APPLICATION_OWNER_CLOSED" }
                else if !scope.active { item.reason = "ACCESS_ENDED_BEFORE_ADMISSION" }
                else if context.current != nil { item.reason = "CALLBACK_CONTEXT_BUSY" }
                else {
                    var admitted: URL? = original
                    if driver == .nativeCandidate, let nativeInputAdmission {
                        do {
                            admitted = try nativeInputAdmission(original)
                            if admitted == nil {
                                throw NativeInputRejectionB7b(stage: .provider, code: .providerDeclined)
                            }
                        } catch let rejection as NativeInputRejectionB7b {
                            admitted = nil; item.nativeInputRejection = rejection
                        } catch {
                            admitted = nil
                            item.nativeInputRejection = NativeInputRejectionB7b(stage: .provider,
                                code: .unexpectedProviderFailure)
                        }
                    }
                    if let admitted {
                        context.current = (scope, admitted)
                        admissionAttempts += 1; item.jobAdmissionAttempted = true
                        let result = applicationOwner.acceptMany([admitted])[0]
                        context.current = nil
                        item.jobID = result.jobID; item.disposition = result.disposition; item.reason = result.reason
                    } else {
                        item.reason = "EXACT_NATIVE_INPUT_NOT_QUALIFIED"
                    }
                }
                scope.end(); item.ended = true
            }
            items.append(item)
        }
        return finish(items)
    }
}

@MainActor
private final class IngressBridgeB7b {
    weak var root: MacAppBootstrapB7b?
    func receive(_ urls: [URL], _ origin: IngressOriginB7b) -> IngressBatchB7b {
        root?.receive(urls, origin: origin) ?? IngressBatchB7b(origin: origin, items: [])
    }
}
@MainActor
enum ProcessBootstrapOwnerB7b {
    private(set) static var retained: MacAppBootstrapB7b?
    static func retain(_ root: MacAppBootstrapB7b) throws {
        guard retained == nil else { throw BootstrapFaultB7b.duplicateBootstrap }
        retained = root
    }
    static func releaseClosedOwner(_ owner: ApplicationJobsB) throws {
        guard let root = retained, root.applicationOwner === owner, owner.store.isClosed else { throw BootstrapFaultB7b.ownerStillOpen }
        retained = nil
    }
}
