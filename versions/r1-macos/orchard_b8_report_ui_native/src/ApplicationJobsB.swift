struct QueueAdmissionB: Encodable {
    var inputIndex: Int
    var jobID: UUID?
    var disposition: String
    var reason: String
}
func admissionReasonB(_ error: Error, maxInputBytes: Int64 = 256) -> String {
    switch error {
    case JobFaultB.waitingCapacity: return "合成待機件数の上限・受付しません"
    case JobFaultB.retainedCapacity: return "合成保持件数の上限・受付しません"
    case JobFaultB.storageCapacity: return "合成保存容量の予約不足・受付しません"
    case JobFaultB.inputCapacity: return maxInputBytes == 256 ? "合成256bytes上限外・受付しません" : "ZIP入力8MiB上限外・受付しません"
    case JobFaultB.duplicate: return "同一入力は登録済み・再受付しません"
    default: return "判断不能・受付保留: \(error)"
    }
}

// The application owns jobs. Windows only read snapshots; no A/C worker exists.
import Foundation
import Darwin

struct JobSnapshotB: Encodable {
    var job: RecordJobB
    var displayState: StateJobB
    var label: String
    var persistenceConfirmed: Bool
    var actualInspectionAnimation: Bool
    var simulatedAnimation: Bool
    var reviewRequired: Bool
}

struct ApplicationViewJobsB: Encodable {
    var jobs: [JobSnapshotB]
    var globalHold: Bool
    var unownedAreaCount: Int
    var actualInspectionConnected: Bool
    var limits: QueueLimitsB
    var queueArmed: Bool
    var currentConditionsConfirmed: Bool
    var activeJobID: UUID?
    var heldWorkerFDs: Int
    var queueHoldReason: String
    var recentAdmissions: [QueueAdmissionB]
}

final class ApplicationJobsB {
    let store: PersistentJobsB
    private let serial = DispatchQueue(label: "Orchard.B.AppOwnedJobs")
    private let queueKey = DispatchSpecificKey<Bool>()
    private var work = [UUID: DispatchWorkItem]()
    private var receivers = [UUID: ZipDropReceiverB]()
    private var stopping = false
    private var workerPins = [UUID: PinnedRead54]()
    private var activeJobID: UUID?
    private var queueArmed = false
    private var conditionsReady = false
    private var queueSteps = 3
    private var queueDelay = 0.02
    private var queueHoldReason = "SYNTHETIC_QUEUE_NOT_ARMED"
    private var recentAdmissions = [QueueAdmissionB]()
    var extractionCheckpoint: (String) throws -> Void = { _ in }
    private(set) var extractionRenameCalls = 0
    var beforeWorkerRelease: () throws -> Void = {}
    private(set) var unownedAreas = [String]()
    private(set) var intakeCalls = 0
    private(set) var syntheticStarts = 0
    var beforeCleanup: () throws -> Void = {}
    var afterCopyBeforeRecord: () throws -> Void = {}
    let receiverFactory: (URL) -> ZipDropReceiverB

    init(store: PersistentJobsB, receiverFactory: @escaping (URL) -> ZipDropReceiverB) throws {
        self.store = store; self.receiverFactory = receiverFactory
        serial.setSpecific(key: queueKey, value: true)
        try store.append("APPLICATION_SESSION_OPEN")
        for old in Array(store.records.values) {
            var r = old
            if old.extraction != nil {
                r = try reconcileExtractionReadOnly(old)
                if try canonicalJobB(r) != canonicalJobB(old) {
                    r.revision += 1; try store.append("EXTRACTION_RECONCILE_READ_ONLY_NO_RETRY", job: r)
                }
                continue
            }
            do { try verifyArtifact(r) }
            catch { r.state = .unknown; r.reason = "RECOVERED_ARTIFACT_MISMATCH_NO_DELETE_NO_RETRY" }
            if r.state != .unknown && ([.receiving, .accepted, .waiting, .inspecting].contains(r.state) || [.held, .releasePending].contains(r.resources)) {
                r.state = r.artifact == nil ? .unknown : .interrupted
                r.reason = "PREVIOUS_APPLICATION_ENDED_NO_AUTOMATIC_RESUME"
            }
            if [.held, .releasePending].contains(r.resources) { r.resources = .unknownAfterRestart }
            if try canonicalJobB(r) != canonicalJobB(old) {
                r.recoveryFrom = "\(old.state.rawValue):\(old.reason)"
            }
            if r.cleanup == "REQUESTED" { r.state = .unknown; r.reason = "CLEANUP_OUTCOME_UNCONFIRMED" }
            if try canonicalJobB(r) != canonicalJobB(old) {
                r.revision += 1; try store.append("RECOVERY_READBACK_ONLY", job: r)
            }
        }
        let claimed = Set(store.records.values.compactMap { r -> String? in
            r.cleanup == "REMOVED" ? nil : r.artifact?.areaName
        })
        unownedAreas = try FileManager.default.contentsOfDirectory(atPath: store.waiting.path).filter { !claimed.contains($0) }
    }

    private func sync<T>(_ body: () throws -> T) rethrows -> T {
        if DispatchQueue.getSpecific(key: queueKey) == true { return try body() }
        return try serial.sync(execute: body)
    }

    private func admitMutation() throws {
        guard !stopping, !store.isClosed else { throw JobFaultB.closed }
        guard store.healthy, unownedAreas.isEmpty else { throw JobFaultB.recoveryHold }
        try store.verifyDirectories()
    }

    @discardableResult
    func accept(_ urls: [URL]) throws -> UUID {
        try sync {
            try admitMutation()
            guard urls.count == 1, urls[0].isFileURL else { throw JobFaultB.binding }
            let source = try statJobB(urls[0])
            let key = "\(source.st_dev):\(source.st_ino)"
            guard !store.records.values.contains(where: { $0.sourceKey == key }) else { throw JobFaultB.duplicate }
            let retained = store.records.values.filter { $0.cleanup != "REMOVED" }
            let waitingCount = retained.filter { [.receiving, .accepted, .waiting].contains($0.state) && $0.workerID == nil }.count
            guard retained.count < store.anchor.limits.retainedJobs else { throw JobFaultB.retainedCapacity }
            guard waitingCount < store.anchor.limits.waitingJobs else { throw JobFaultB.waitingCapacity }
            guard source.st_size > 0, source.st_size <= store.maxIntakeBytes else { throw JobFaultB.inputCapacity }
            let reservation = store.productQualification ? Int64(source.st_size) : 256
            guard retained.reduce(Int64(0), { $0 + $1.reservedBytes }) + reservation <= store.anchor.limits.retainedBytes else { throw JobFaultB.storageCapacity }
            let order = (store.records.values.map(\.queueOrder).max() ?? 0) + 1
            let id = UUID()
            var r = RecordJobB(jobID: id, ownerID: store.registration.ownerID, storeID: store.registration.storeID,
                sourceKey: key, revision: 1, queueOrder: order, reservedBytes: reservation, workerEnded: false,
                resources: .none, recoveryFrom: nil, extraction: nil, state: .receiving, reason: "ADMISSION_RESERVED_BEFORE_COPY",
                artifact: nil, intakeInputID: nil, intakeAttemptID: nil, workerScope: .notConnected,
                workerID: nil, progress: 0, target: 0, cleanup: "NONE", actualInspectionStarted: false,
                actualInspectionCompleted: false, authorityIssued: false, aConnected: false)
            try store.append("ADMISSION_RESERVED_NO_RETRY", job: r)
            let receiver = receiverFactory(store.waiting)
            receivers[id] = receiver
            intakeCalls += 1
            let result = receiver.receive(urls)
            guard result.state == "WAITING", let receipt = result.receipt, let area = receiver.pending else {
                r.state = .unknown; r.reason = "INTAKE_UNCONFIRMED_NO_AUTOMATIC_RETRY"; r.revision += 1
                r.intakeProtectionFailure = result.protection
                try store.append("INTAKE_HELD", job: r); return id
            }
            let areaStat = try statJobB(area.areaURL), leaf = try statJobB(area.outputURL)
            r.artifact = ArtifactJobB(areaName: area.areaName, area: StampJobB(areaStat), leaf: StampJobB(leaf),
                size: receipt.size, sha256: receipt.sha256, protection: result.protection)
            r.intakeInputID = receipt.inputID; r.intakeAttemptID = receipt.attemptID
            r.reservedBytes = receipt.size
            do {
                try afterCopyBeforeRecord()
                try verifyArtifact(r)
                try receiver.releaseStagingHandles(); receivers[id] = nil
            } catch {
                r.state = .unknown; r.reason = "POST_RECEIPT_PROTECTION_OR_IDENTITY_HOLD_NO_ACCEPTANCE"; r.revision += 1
                try store.append("ACCEPTANCE_PROTECTION_HOLD", job: r)
                throw error
            }
            r.state = .accepted; r.reason = "OPAQUE_COPY_VERIFIED_NOT_INSPECTED"; r.revision += 1
            try store.append("ACCEPTANCE_VERIFIED", job: r)
            r.state = .waiting; r.reason = "A_C_NOT_CONNECTED"; r.revision += 1
            try store.append("WAITING_NO_ACTUAL_INSPECTION", job: r)
            return id
        }
    }

    func acceptMany(_ urls: [URL]) -> [QueueAdmissionB] {
        sync {
            var results = [QueueAdmissionB]()
            for (index, url) in urls.enumerated() {
                do {
                    let id = try accept([url]), r = store.records[id]!
                    results.append(QueueAdmissionB(inputIndex: index, jobID: id,
                        disposition: r.state == .waiting ? "ACCEPTED_WAITING" : "HOLD", reason: r.reason))
                } catch {
                    results.append(QueueAdmissionB(inputIndex: index, jobID: nil,
                        disposition: "REJECTED_OR_HOLD", reason: admissionReasonB(error, maxInputBytes: store.maxIntakeBytes)))
                }
            }
            recentAdmissions = results
            return results
        }
    }

    func selectSyntheticExtraction(_ id: UUID, destinationParent: URL, leaf: String) throws -> SyntheticExtractionSelectionB {
        try sync {
            try admitMutation()
            guard validExtractionLeafB(leaf), destinationParent.isFileURL,
                  let r = store.records[id], r.extraction == nil else { throw ExtractionFaultB.selection }
            try requireExtractionStopped(r)
            try verifyArtifact(r)
            let path = try selectedDestinationPathB(destinationParent)
            for forbidden in [store.root.path, store.waiting.path] {
                guard path != forbidden, !path.hasPrefix(forbidden + "/") else { throw ExtractionFaultB.selection }
            }
            var directory = try directoryExtractionB(destinationParent).0
            defer { _ = closeFD_B(&directory) }
            try rejectStoreAncestorExtractionB(directory, store: store)
            var info = stat(); guard fstat(directory, &info) == 0 else { throw ExtractionFaultB.identity }
            guard try absentExtractionB(directory, leaf) else { throw ExtractionFaultB.destinationExists }
            guard Int64(info.st_dev) == r.artifact?.leaf.dev else { throw ExtractionFaultB.differentVolume }
            return SyntheticExtractionSelectionB(requestID: UUID(), jobID: id, ownerID: r.ownerID,
                storeID: r.storeID, sessionID: store.sessionID, revision: r.revision,
                artifactDigest: hash54(try canonicalJobB(r.artifact)), destinationParentPath: path,
                destinationParent: StampJobB(info), destinationLeaf: leaf)
        }
    }

    private func requireExtractionStopped(_ r: RecordJobB) throws {
        guard [.waiting, .finished, .interrupted].contains(r.state), activeJobID != r.jobID,
              workerPins[r.jobID] == nil, ![WorkerResourcesB.held, .releasePending, .unknownAfterRestart].contains(r.resources),
              r.workerID == nil || (r.workerEnded && r.resources == .released) else { throw ExtractionFaultB.busy }
    }

    @discardableResult
    func extractSyntheticSameVolume(_ selection: SyntheticExtractionSelectionB) throws -> RecordJobB {
        try sync {
            try admitMutation()
            guard var r = store.records[selection.jobID], r.extraction == nil,
                  selection.ownerID == store.registration.ownerID, selection.storeID == store.registration.storeID,
                  selection.sessionID == store.sessionID, selection.revision == r.revision,
                  selection.artifactDigest == hash54(try canonicalJobB(r.artifact)) else { throw ExtractionFaultB.stale }
            try requireExtractionStopped(r); try verifyArtifact(r)
            guard validExtractionLeafB(selection.destinationLeaf) else { throw ExtractionFaultB.selection }
            for forbidden in [store.root.path, store.waiting.path] {
                let path = try selectedDestinationPathB(URL(fileURLWithPath: selection.destinationParentPath))
                guard path != forbidden, !path.hasPrefix(forbidden + "/") else { throw ExtractionFaultB.selection }
            }
            let bound = try BoundSyntheticMoveB(store: store, job: r, selection: selection)
            defer { _ = bound.closeAll() }
            r.extraction = ExtractionTransferB(requestID: selection.requestID, jobID: r.jobID,
                ownerID: r.ownerID, storeID: r.storeID, sessionID: store.sessionID,
                requestedRevision: selection.revision, sourceArtifactSHA256: r.artifact!.sha256,
                sourceArtifactDigest: selection.artifactDigest, destinationParentPath: selection.destinationParentPath,
                destinationParent: selection.destinationParent, destinationLeaf: selection.destinationLeaf,
                metadata: bound.metadata, phase: .intent, destinationStamp: nil, handlesClosed: false, holdReason: nil)
            r.state = .extracting; r.reason = "EXPLICIT_SYNTHETIC_EXTRACTION_RESERVED_NO_RETRY"; r.revision += 1
            try store.append("EXTRACTION_INTENT_NO_RETRY", job: r)
            do {
                try extractionCheckpoint("after_intent")
                try extractionCheckpoint("before_rename")
                try bound.verifyBefore()
                try extractionCheckpoint("last_edge_before_rename")
                extractionRenameCalls += 1
                try bound.renameExclusive()
                try extractionCheckpoint("after_rename")
                let stamp = try bound.verifyAfter()
                try bound.synchronize()
                r.extraction!.phase = .renamedSynced; r.extraction!.destinationStamp = stamp
                r.reason = "RENAMED_REVERIFIED_DIR_FSYNC_ACK_NO_INSPECTION_RESULT"; r.revision += 1
                try store.append("EXTRACTION_RENAMED_AND_SYNCED", job: r)
                try extractionCheckpoint("after_synced_record")
                guard bound.closeAll() else { throw ExtractionFaultB.io }
                try extractionCheckpoint("after_handles_closed")
                r.extraction!.handlesClosed = true; r.extraction!.phase = .completed
                r.state = .extracted; r.cleanup = "EXTRACTED"; r.reservedBytes = 0
                r.reason = "SYNTHETIC_EXTRACTION_CONFIRMED_NO_SAFETY_VERDICT"; r.revision += 1
                try store.append("EXTRACTION_COMPLETE_HANDLES_RELEASED", job: r)
                return r
            } catch {
                if store.healthy, !store.isClosed, var held = store.records[r.jobID] {
                    held.state = .unknown; held.reason = "EXTRACTION_OUTCOME_HOLD_NO_AUTOMATIC_MOVE_OR_DELETE"
                    held.extraction?.holdReason = String(describing: error); held.revision += 1
                    try store.append("EXTRACTION_HOLD_NO_RETRY", job: held)
                }
                throw error
            }
        }
    }

    private func reconcileExtractionReadOnly(_ old: RecordJobB) throws -> RecordJobB {
        var r = old
        guard var transfer = r.extraction else { return r }
        do {
            let observation = try observeExtractionB(store: store, job: r)
            if observation.location == .destination && [.renamedSynced, .completed].contains(transfer.phase) {
                transfer.phase = .completed; transfer.handlesClosed = true; transfer.destinationStamp = observation.destinationStamp
                r.extraction = transfer; r.state = .extracted; r.reservedBytes = 0
                if r.cleanup != "REMOVED" { r.cleanup = "EXTRACTED" }
                if old.state != .extracted { r.reason = "RECOVERED_SAVED_MOVE_ACK_READBACK_NO_NEW_MOVE" }
            } else if observation.location == .source && transfer.phase == .intent {
                r.state = .interrupted; r.reason = "EXTRACTION_SOURCE_UNMOVED_OBSERVED_NO_AUTOMATIC_RETRY"
            } else {
                r.state = .unknown; r.reason = "EXTRACTION_DESTINATION_OBSERVED_WITHOUT_DURABLE_ACK_HOLD"
            }
        } catch {
            r.state = .unknown; r.reason = "EXTRACTION_OWNER_OBJECT_OR_LOCATION_MISMATCH_HOLD_NO_DELETE"
        }
        if r.state != old.state || r.reason != old.reason { r.recoveryFrom = "\(old.state.rawValue):\(old.reason)" }
        return r
    }

    func actualGardens() -> GardensViewB {
        sync {
            // No consumer import path exists in this case. Never infer a C result from B job state.
            actualGardensViewB(store.records.values.sorted { $0.queueOrder < $1.queueOrder })
        }
    }

    func snapshots() -> [JobSnapshotB] {
        sync { store.records.values.sorted { $0.queueOrder < $1.queueOrder }.map(project) }
    }

    func viewState() -> ApplicationViewJobsB {
        sync { ApplicationViewJobsB(jobs: store.records.values.sorted { $0.queueOrder < $1.queueOrder }.map(project),
            globalHold: !store.healthy || !unownedAreas.isEmpty,
            unownedAreaCount: unownedAreas.count, actualInspectionConnected: false, limits: store.anchor.limits,
            queueArmed: queueArmed, currentConditionsConfirmed: conditionsReady, activeJobID: activeJobID,
            heldWorkerFDs: workerPins.count, queueHoldReason: queueHoldReason, recentAdmissions: recentAdmissions) }
    }

    func snapshot(_ id: UUID) throws -> JobSnapshotB {
        try sync {
            guard let r = store.records[id] else { throw JobFaultB.binding }
            return project(r)
        }
    }

    // A9 product-offline path: the currently waiting owned copy is bound to a
    // read-only FD for one inspection. Existing v5 and interrupted jobs cannot enter.
    func withCurrentWaitingZIP<T>(_ id: UUID,
                                  body: (RecordJobB, Int32, FileIdentity54) throws -> T) throws -> T {
        try sync {
            try admitMutation()
            guard store.productQualification, let r = store.records[id], r.state == .waiting,
                  r.workerScope == .notConnected, r.workerID == nil, r.resources == .none,
                  !r.actualInspectionStarted, !r.actualInspectionCompleted,
                  !r.authorityIssued, !r.aConnected, r.cleanup == "NONE",
                  let a = r.artifact, r.intakeInputID != nil, r.intakeAttemptID != nil else {
                throw JobFaultB.binding
            }
            try verifyArtifact(r)
            let leaf = store.waiting.appendingPathComponent(a.areaName, isDirectory: true)
                .appendingPathComponent("pending.zip")
            let fd = Darwin.open(leaf.path, O_RDONLY | O_NOFOLLOW_ANY | O_CLOEXEC)
            guard fd >= 0 else { throw JobFaultB.artifactMismatch }
            defer { _ = Darwin.close(fd) }
            var actual = stat(), path = stat()
            guard fstat(fd, &actual) == 0, lstat(leaf.path, &path) == 0,
                  a.leaf.exact(actual), a.leaf.exact(path), actual.st_size == a.size,
                  actual.st_uid == geteuid(), actual.st_nlink == 1 else { throw JobFaultB.artifactMismatch }
            let identity = FileIdentity54(actual)
            let pin = try PinnedRead54(url: leaf, size: a.size, sha256: a.sha256)
            var pinOpen = false
            defer { if pinOpen { _ = pin.closeOwned() } }
            try pin.openAndPin(selectedFD: fd, selectedIdentity: identity) {}
            pinOpen = true
            let outcome = try body(r, fd, identity)
            try pin.verifyPathAndFD()
            guard pin.closeOwned(), store.records[id]?.revision == r.revision else { throw JobFaultB.artifactMismatch }
            pinOpen = false
            return outcome
        }
    }

    private func project(_ r: RecordJobB) -> JobSnapshotB {
        let state: StateJobB = store.healthy ? r.state : .unknown
        let simulated = r.workerScope == .syntheticOnly
        let label: String
        switch state {
        case .receiving: label = "受け入れ未完了"
        case .accepted: label = "受け入れ成功・未検査"
        case .waiting: label = "検査待ち・A/C未接続"
        case .inspecting: label = simulated ? "模擬検査中・実検査ではない" : "判断不能"
        case .finished: label = simulated ? "模擬検査終了・実検査結果なし" : "判断不能"
        case .interrupted: label = "中断・自動再試行なし"
        case .unknown: label = "判断不能・要照合"
        case .extracting: label = "合成ZIP取り出し中・検査結果ではない"
        case .extracted: label = "合成ZIP取り出し確認済み・安全判定なし"
        }
        return JobSnapshotB(job: r, displayState: state, label: label, persistenceConfirmed: store.healthy,
            actualInspectionAnimation: false,
            simulatedAnimation: store.healthy && simulated && state == .inspecting && r.progress > 0,
            reviewRequired: state == .unknown || !unownedAreas.isEmpty)
    }

    // This queue only advances an opaque toy counter; it never parses ZIP or supplies C results.
    func setSyntheticConditions(_ confirmed: Bool) throws {
        try sync { try admitMutation(); conditionsReady = confirmed
            try store.append(confirmed ? "SYNTHETIC_CONDITIONS_CONFIRMED" : "SYNTHETIC_CONDITIONS_WITHHELD")
            if queueArmed { try pumpSynthetic() }
        }
    }

    func armSyntheticQueue(steps: Int = 3, delay: Double = 0.02) throws {
        try sync {
            try admitMutation()
            guard steps > 0, steps <= 100, delay >= 0.005, delay <= 1 else { throw JobFaultB.binding }
            guard !queueArmed else { throw JobFaultB.duplicate }
            queueSteps = steps; queueDelay = delay; queueArmed = true
            try store.append("SYNTHETIC_QUEUE_ARMED_CURRENT_SESSION_ONLY")
            do { try pumpSynthetic() }
            catch { queueArmed = false; queueHoldReason = "START_HOLD_NO_AUTOMATIC_RETRY"; throw error }
        }
    }

    private func pumpSynthetic() throws {
        guard queueArmed, !stopping else { return }
        try admitMutation()
        guard activeJobID == nil, workerPins.isEmpty else { queueHoldReason = "ONE_WORKER_OR_RELEASE_PENDING"; return }
        guard conditionsReady else { queueHoldReason = "NEXT_EXECUTION_CONDITIONS_NOT_CONFIRMED"; return }
        let ordered = store.records.values.sorted { $0.queueOrder < $1.queueOrder }
        guard var r = ordered.first(where: { $0.state == .waiting && $0.workerID == nil }) else {
            queueHoldReason = "NO_ELIGIBLE_WAITING_JOB_NO_RESUME"; return
        }
        guard ordered.filter({ $0.queueOrder < r.queueOrder }).allSatisfy({
            ([.finished, .interrupted].contains($0.state) && $0.workerEnded && $0.resources == .released)
                || ($0.state == .extracted && $0.extraction?.phase == .completed)
        }) else { queueHoldReason = "EARLIER_JOB_END_OR_RELEASE_UNCONFIRMED"; return }
        guard !ordered.contains(where: { [.held, .releasePending, .unknownAfterRestart].contains($0.resources) }) else {
            queueHoldReason = "PREVIOUS_RESOURCES_UNCONFIRMED"; return
        }
        try verifyArtifact(r)
        let pin = try acquireWorkerPin(r)
        let token = UUID()
        r.workerID = token; r.workerScope = .syntheticOnly; r.resources = .held
        r.target = queueSteps; r.reason = "SYNTHETIC_WORKER_RESERVED_NOT_ACTUAL_INSPECTION"; r.revision += 1
        do { try store.append("SYNTHETIC_RESERVED", job: r) }
        catch { _ = pin.closeOwned(); throw error }
        workerPins[r.jobID] = pin; activeJobID = r.jobID
        syntheticStarts += 1; queueHoldReason = "ONE_SYNTHETIC_WORKER_RUNNING"
        schedule(r.jobID, token: token, delay: queueDelay)
    }

    private func acquireWorkerPin(_ r: RecordJobB) throws -> PinnedRead54 {
        guard let a = r.artifact else { throw JobFaultB.artifactMismatch }
        let url = store.waiting.appendingPathComponent(a.areaName).appendingPathComponent("pending.zip")
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard fd >= 0 else { throw JobFaultB.artifactMismatch }
        defer { _ = Darwin.close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, a.leaf.exact(info) else { throw JobFaultB.artifactMismatch }
        let pin = try PinnedRead54(url: url, size: a.size, sha256: a.sha256)
        do { try pin.openAndPin(selectedFD: fd, selectedIdentity: FileIdentity54(info)) {} }
        catch { _ = pin.closeOwned(); throw error }
        return pin
    }

    private func schedule(_ id: UUID, token: UUID, delay: Double) {
        let item = DispatchWorkItem { [weak self] in
            guard let self, let current = self.store.records[id], current.workerID == token,
                  current.resources == .held, [.waiting, .inspecting].contains(current.state) else { return }
            do { try self.advanceSynthetic(id, token: token, delay: delay) }
            catch {
                self.work[id] = nil
                if self.store.healthy, !self.store.isClosed, var r = self.store.records[id] {
                    r.state = .unknown; r.reason = "SYNTHETIC_FAILURE_NO_ACTUAL_RESULT"; r.resources = .releasePending; r.revision += 1
                    try? self.store.append("SYNTHETIC_FAILURE_UNKNOWN", job: r)
                    self.enqueueRelease(id, token: token)
                }
            }
        }
        work[id] = item
        serial.asyncAfter(deadline: .now() + delay, execute: item)
    }

    private func advanceSynthetic(_ id: UUID, token: UUID, delay: Double) throws {
        try admitMutation()
        guard activeJobID == id, var r = store.records[id], r.workerScope == .syntheticOnly,
              r.workerID == token, r.resources == .held else { throw JobFaultB.workerIdentity }
        try verifyArtifact(r); try workerPins[id]?.verifyPathAndFD()
        r.progress += 1; r.state = r.progress == r.target ? .finished : .inspecting
        r.reason = r.state == .finished ? "SYNTHETIC_COMPLETION_ONLY_RELEASE_PENDING" : "SYNTHETIC_TICK_OBSERVED"
        if r.state == .finished { r.resources = .releasePending }
        r.revision += 1
        try store.append(r.state == .finished ? "SYNTHETIC_FINISHED_RELEASE_PENDING" : "SYNTHETIC_TICK", job: r)
        if r.state == .finished { work[id] = nil; enqueueRelease(id, token: token) }
        else { schedule(id, token: token, delay: delay) }
    }

    private func enqueueRelease(_ id: UUID, token: UUID) {
        // A later serial turn can only run after the previous tick/cancel callback returned.
        serial.async { [weak self] in self?.confirmWorkerExitAndRelease(id, token: token) }
    }

    private func confirmWorkerExitAndRelease(_ id: UUID, token: UUID) {
        guard !stopping, store.healthy, !store.isClosed, activeJobID == id,
              var r = store.records[id], r.workerID == token else { return }
        do {
            try beforeWorkerRelease()
            guard let pin = workerPins[id] else { throw JobFaultB.resourceRelease }
            try pin.verifyPathAndFD()
            guard pin.closeOwned() else { throw JobFaultB.resourceRelease }
            workerPins[id] = nil; work[id] = nil
            r.workerEnded = true; r.resources = .released
            if r.state == .interrupted { r.reason = "SYNTHETIC_CANCEL_STOP_RELEASE_CONFIRMED" }
            r.revision += 1
            try store.append("SYNTHETIC_CALLBACK_EXIT_AND_FD_RELEASE_CONFIRMED", job: r)
            activeJobID = nil
        } catch {
            queueArmed = false
            queueHoldReason = "WORKER_RELEASE_OR_NEXT_START_UNCONFIRMED"
            if store.healthy, !store.isClosed {
                r.state = .unknown; r.reason = "WORKER_RELEASE_OR_NEXT_START_HOLD"; r.revision += 1
                try? store.append("QUEUE_RELEASE_HOLD", job: r)
            }
            return
        }
        do { try pumpSynthetic() }
        catch { queueArmed = false; queueHoldReason = "NEXT_START_HOLD_NO_NEW_WORKER" }
    }

    func cancel(_ id: UUID) throws {
        try sync {
            try admitMutation()
            guard var r = store.records[id], [.receiving, .accepted, .waiting, .inspecting].contains(r.state) else { throw JobFaultB.state }
            work[id]?.cancel(); work[id] = nil
            r.state = .interrupted; r.reason = "EXPLICIT_CANCEL_WAITING_FOR_STOP_RELEASE"
            r.resources = r.workerID == nil ? .released : .releasePending
            r.workerEnded = r.workerID == nil; r.revision += 1
            try store.append("EXPLICIT_CANCEL_REQUESTED", job: r)
            if let token = r.workerID { enqueueRelease(id, token: token) }
            else { try pumpSynthetic() }
        }
    }

    func rejectForeignCompletion(_ id: UUID, token: UUID) throws {
        try sync {
            guard let r = store.records[id], r.workerID == token else { throw JobFaultB.workerIdentity }
            // No external completion entry is connected, even with a matching UUID.
            throw JobFaultB.state
        }
    }

    func verifyArtifact(_ r: RecordJobB) throws {
        try store.verifyDirectories()
        if r.extraction != nil {
            let observed = try observeExtractionB(store: store, job: r)
            guard r.extraction?.phase == .completed, observed.location == .destination,
                  observed.destinationStamp == r.extraction?.destinationStamp else { throw JobFaultB.artifactMismatch }
            return
        }
        guard let a = r.artifact else {
            if r.state == .receiving || r.state == .unknown || r.state == .interrupted { return }
            throw JobFaultB.artifactMismatch
        }
        let area = store.waiting.appendingPathComponent(a.areaName, isDirectory: true)
        if r.cleanup == "REMOVED" {
            var value = stat(); errno = 0
            guard lstat(area.path, &value) == -1 && errno == ENOENT else { throw JobFaultB.artifactMismatch }
            return
        }
        let areaInfo = try statJobB(area)
        let leaf = area.appendingPathComponent("pending.zip"), leafInfo = try statJobB(leaf)
        guard a.area.directory(areaInfo), a.leaf.exact(leafInfo), leafInfo.st_nlink == 1,
              leafInfo.st_uid == geteuid(), [mode_t(0o400), mode_t(0o600)].contains(leafInfo.st_mode & 0o7777),
              Set(try FileManager.default.contentsOfDirectory(atPath: area.path)) == ["pending.zip"] else { throw JobFaultB.artifactMismatch }
        let fd = Darwin.open(leaf.path, O_RDONLY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard fd >= 0 else { throw JobFaultB.artifactMismatch }; defer { _ = Darwin.close(fd) }
        let pin = try PinnedRead54(url: leaf, size: a.size, sha256: a.sha256)
        do { try pin.openAndPin(selectedFD: fd, selectedIdentity: FileIdentity54(leafInfo)) {} }
        catch { _ = pin.closeOwned(); throw error }
        guard pin.closeOwned() else { throw JobFaultB.io }
        guard let proof = a.protection else { throw JobFaultB.artifactMismatch }
        try verifyStoredProtectionB(fd, evidence: proof, strictIdentity: true)
    }

    func recoverOwnedCopy(_ id: UUID) throws {
        try sync {
            try admitMutation()
            if var moved = store.records[id], moved.state == .extracted {
                do {
                    try verifyArtifact(moved); try beforeCleanup()
                    try removeEmptyExtractedAreaB(store: store, job: moved)
                    moved.cleanup = "REMOVED"; moved.revision += 1
                    try store.append("EXTRACTED_EMPTY_AREA_REMOVED_DESTINATION_UNCHANGED", job: moved)
                    return
                } catch {
                    if store.healthy {
                        moved.state = .unknown; moved.reason = "EXTRACTED_AREA_CLEANUP_HOLD_DESTINATION_UNTOUCHED"; moved.revision += 1
                        try store.append("EXTRACTED_AREA_CLEANUP_HOLD", job: moved)
                    }
                    throw error
                }
            }
            guard var r = store.records[id], [.interrupted, .unknown, .finished].contains(r.state),
                  let artifact = r.artifact, activeJobID != id, workerPins[id] == nil,
                  ![WorkerResourcesB.held, .releasePending].contains(r.resources) else { throw JobFaultB.recoveryHold }
            if r.cleanup == "REMOVED" { try verifyArtifact(r); return }
            do {
                try verifyArtifact(r)
                r.cleanup = "REQUESTED"; r.revision += 1
                try store.append("EXPLICIT_OWNED_CLEANUP_REQUESTED", job: r)
                try beforeCleanup()
                if let receiver = receivers[id] {
                    _ = try receiver.discardPending(); receivers[id] = nil
                } else {
                    try removeRecoveredArtifact(artifact)
                }
                r.cleanup = "REMOVED"; r.reservedBytes = 0; r.reason = "OWNED_COPY_REMOVED_NO_RETRY"; r.revision += 1
                try store.append("OWNED_COPY_ABSENCE_CONFIRMED", job: r)
            } catch {
                if store.healthy {
                    var held = store.records[id] ?? r
                    held.state = .unknown; held.cleanup = "HOLD"; held.reason = "RECOVERY_FAILED_NO_FOREIGN_DELETE"
                    held.revision += 1; try store.append("RECOVERY_HOLD", job: held)
                }
                throw error
            }
        }
    }

    private func removeRecoveredArtifact(_ a: ArtifactJobB) throws {
        let parent = Darwin.open(store.waiting.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC)
        guard parent >= 0 else { throw JobFaultB.recoveryHold }; defer { _ = Darwin.close(parent) }
        let area = openat(parent, a.areaName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard area >= 0 else { throw JobFaultB.recoveryHold }; defer { _ = Darwin.close(area) }
        var value = stat(), path = stat(), leaf = stat()
        guard fstat(area, &value) == 0, fstatat(parent, a.areaName, &path, AT_SYMLINK_NOFOLLOW) == 0,
              a.area.directory(value), a.area.directory(path),
              fstatat(area, "pending.zip", &leaf, AT_SYMLINK_NOFOLLOW) == 0, a.leaf.exact(leaf) else { throw JobFaultB.artifactMismatch }
        guard unlinkat(area, "pending.zip", 0) == 0, fsync(area) == 0,
              unlinkat(parent, a.areaName, AT_REMOVEDIR) == 0, fsync(parent) == 0 else { throw JobFaultB.io }
        errno = 0
        guard fstatat(parent, a.areaName, &value, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT else { throw JobFaultB.io }
    }

    func applicationQuit() throws {
        try sync {
            if stopping { return }
            stopping = true; queueArmed = false; conditionsReady = false
            for item in work.values { item.cancel() }; work.removeAll()
            defer { receivers.removeAll(); store.close() }
            for pin in workerPins.values { guard pin.closeOwned() else { throw JobFaultB.resourceRelease } }
            workerPins.removeAll(); activeJobID = nil
            guard store.healthy else { throw JobFaultB.persistenceUnknown }
            for var r in Array(store.records.values) where [.receiving, .accepted, .waiting, .inspecting].contains(r.state) {
                r.recoveryFrom = "\(r.state.rawValue):\(r.reason)"
                r.state = r.artifact == nil ? .unknown : .interrupted
                r.reason = "APPLICATION_QUIT_NOT_WINDOW_CLOSE"
                if r.workerID != nil { r.resources = .released; r.workerEnded = true }; r.revision += 1
                try store.append("APPLICATION_QUIT_INTERRUPTED", job: r)
            }
        }
    }

    deinit { for item in work.values { item.cancel() }; for pin in workerPins.values { _ = pin.closeOwned() }; store.close() }
}

// This object has no acceptance/start/cancel method and never owns a job.
final class WindowProjectionJobsB {
    weak var applicationOwner: ApplicationJobsB?
    private(set) var visible = false
    init(applicationOwner: ApplicationJobsB) { self.applicationOwner = applicationOwner }
    func windowClosed() { visible = false }
    func windowReopened() -> [JobSnapshotB] { visible = true; return applicationOwner?.snapshots() ?? [] }
}
