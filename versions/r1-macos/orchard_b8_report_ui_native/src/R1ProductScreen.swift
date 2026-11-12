// A9 product composition. B8 remains the sole AppKit URL delegate and job
// owner. A3 owns result text and explicit mock-only human choice.
import AppKit
import Foundation

// Old B7cL/Session admissions do not conform. A future native scope must
// explicitly bind the new R1 product source, signed worker, and app identity.
protocol R1ProductNativeAdmission: NativeExecutionAdmissionB7b {
    func verifyR1ProductScope() throws
}

struct HoldR1ProductNativeAdmission: R1ProductNativeAdmission {
    func verifyCurrentNativeScope() throws { throw BootstrapFaultB7b.missingNativeExecutionQualification }
    func verifyR1ProductScope() throws { throw BootstrapFaultB7b.missingNativeExecutionQualification }
}

@MainActor
final class R1ProductScreen: NSView {
    let root: MacAppBootstrapB7b
    let flow: R1ProductFlow
    let inspectButton = NSButton(title: "現在のZIPを検査", target: nil, action: nil)
    private let chooseButton = NSButton(title: "ZIPを選択", target: nil, action: nil)
    private let stopButton = NSButton(title: "検査を停止", target: nil, action: nil)
    private let status = NSTextView()
    private let reviewScroll = NSScrollView()
    private let emptyReview = NSTextField(wrappingLabelWithString:
        "検査結果はまだありません。\n「ZIPを選択」で入力を選び、「現在のZIPを検査」を押してください。\n検査後に結果・根拠・UNKNOWNを確認し、人間が判断します。選択だけでは検査・展開しません。")
    private var extractionButton: NSButton?
    private var extractionStatus: NSTextField?
    private(set) var reviewPanel: R1ReviewPanel?
    private let now: () -> Date
    private var reviewRefreshTimer: Timer?
    var onStateChanged: (() -> Void)?
    var requestZIPSelection: (() -> Void)?

    init(root: MacAppBootstrapB7b, flow: R1ProductFlow, now: @escaping () -> Date = Date.init) {
        self.root = root; self.flow = flow; self.now = now
        super.init(frame: NSRect(x: 0, y: 0, width: 980, height: 720))
        wantsLayer = true
        autoresizingMask = [.width, .height]
        chooseButton.identifier = NSUserInterfaceItemIdentifier("r1.product.choose-zip")
        chooseButton.target = self; chooseButton.action = #selector(chooseAction(_:))
        addSubview(chooseButton)
        inspectButton.identifier = NSUserInterfaceItemIdentifier("r1.product.inspect-current")
        inspectButton.target = self; inspectButton.action = #selector(inspectAction(_:))
        addSubview(inspectButton)
        stopButton.identifier = NSUserInterfaceItemIdentifier("r1.product.stop-current")
        stopButton.target = self; stopButton.action = #selector(stopAction(_:))
        addSubview(stopButton)
        status.isEditable = false; status.isSelectable = false; status.isRichText = false
        status.importsGraphics = false; status.isAutomaticLinkDetectionEnabled = false
        status.isAutomaticDataDetectionEnabled = false
        addSubview(status)
        reviewScroll.hasVerticalScroller = true
        reviewScroll.hasHorizontalScroller = true
        reviewScroll.autohidesScrollers = true
        reviewScroll.borderType = .noBorder
        addSubview(reviewScroll)
        emptyReview.font = NSFont.systemFont(ofSize: 16)
        addSubview(emptyReview)
        root.onIngress = { [weak self] batch in
            self?.flow.receive(batch)
            self?.refresh()
        }
        needsLayout = true
        refresh()
    }
    required init?(coder: NSCoder) { return nil }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        needsLayout = true
    }

    // AppKit can constrain the content view to the display's visible height.
    // Keep review choices in the fixed footer while the result panel scrolls.
    // Confirmation still requires a distinct human action before extraction.
    override func layout() {
        let keepReviewTop = reviewPanel.map {
            reviewScroll.documentVisibleRect.maxY >= $0.bounds.maxY - 1
        } ?? false
        super.layout()
        let width = bounds.width
        let height = bounds.height
        chooseButton.frame = NSRect(x: 24, y: height - 48, width: 160, height: 32)
        inspectButton.frame = NSRect(x: 198, y: height - 48, width: 200, height: 32)
        stopButton.frame = NSRect(x: 412, y: height - 48, width: 110, height: 32)
        status.frame = NSRect(x: 24, y: height - 108, width: width - 48, height: 52)
        reviewScroll.frame = NSRect(x: 10, y: 120, width: width - 20, height: height - 240)
        emptyReview.frame = NSRect(x: 28, y: height - 260, width: width - 56, height: 120)
        reviewPanel?.confirmButton.frame = NSRect(x: 24, y: 72, width: 200, height: 32)
        reviewPanel?.rejectButton.frame = NSRect(x: 238, y: 72, width: 108, height: 32)
        reviewPanel?.cancelButton.frame = NSRect(x: 360, y: 72, width: 108, height: 32)
        extractionButton?.frame = NSRect(x: 24, y: 20, width: 260, height: 32)
        extractionStatus?.frame = NSRect(x: 300, y: 12, width: width - 324, height: 46)
        reviewScroll.layoutSubtreeIfNeeded()
        if keepReviewTop { scrollReviewToTop() }
    }

    func installExtractionControls(button: NSButton, status: NSTextField) {
        extractionButton = button; extractionStatus = status
        addSubview(button); addSubview(status)
        needsLayout = true
    }

    private func scrollReviewToTop() {
        guard let panel = reviewPanel else { return }
        let x = min(max(0, reviewScroll.documentVisibleRect.minX),
                    max(0, panel.bounds.width - reviewScroll.contentSize.width))
        let y = max(0, panel.bounds.height - reviewScroll.contentSize.height)
        reviewScroll.contentView.scroll(to: NSPoint(x: x, y: y))
        reviewScroll.reflectScrolledClipView(reviewScroll.contentView)
    }

    @objc private func inspectAction(_ sender: NSButton) {
        do { try flow.inspectCurrentAsync() }
        catch { /* The flow records a HOLD and consumes this attempt. */ }
        refresh()
    }

    @objc private func chooseAction(_ sender: NSButton) {
        guard chooseButton.isEnabled, flow.canAcceptInput else { return }
        requestZIPSelection?()
    }

    @objc private func stopAction(_ sender: NSButton) {
        guard flow.isInspecting || flow.observationBusy else { return }
        flow.requestStop("EXPLICIT_INSPECTION_STOP")
        refresh()
    }

    func startReviewRefresh() {
        guard reviewRefreshTimer == nil else { return }
        let timer = Timer(timeInterval: 0.25, repeats: true) { [weak self] timer in
            guard self != nil else { timer.invalidate(); return }
            Task { @MainActor [weak self] in self?.refresh() }
        }
        reviewRefreshTimer = timer
        RunLoop.main.add(timer, forMode: .common)
    }

    func stopReviewRefresh() {
        reviewRefreshTimer?.invalidate()
        reviewRefreshTimer = nil
    }

    override func viewWillMove(toWindow newWindow: NSWindow?) {
        if newWindow == nil { stopReviewRefresh() }
        super.viewWillMove(toWindow: newWindow)
    }

    func refresh() {
        flow.recordVisibleReview(origin: "CLOCK_OR_DISPLAY_REFRESH")
        let state = flow.snapshot()
        chooseButton.isEnabled = requestZIPSelection != nil && flow.canAcceptInput
        inspectButton.isEnabled = flow.canInspectCurrent
        stopButton.isEnabled = (flow.isInspecting || flow.observationBusy) && !flow.stopping
        let displayIssue = state.reviewDecision == R1ReviewDecision.expired.rawValue
            ? "確認期限が切れました" : (state.issue ?? "なし")
        let activity = flow.observationBusy ? "動作状態を記録中" : (flow.isInspecting ? "ZIPを検査中" : "現在job")
        status.string = "\(activity): \(state.currentJobID?.uuidString ?? "NONE") / \(state.reviewDecision)\n" +
            "\(state.inspectionStatus) / \(state.promptInjection) / 停止・判断不能: \(displayIssue) / AI引き渡し: HOLD"
        emptyReview.isHidden = flow.session != nil
        reviewScroll.isHidden = flow.session == nil
        if let session = flow.session {
            if reviewPanel == nil {
                let panel = R1ReviewPanel(frame: NSRect(x: 0, y: 0, width: 960, height: 820),
                                          session: session, now: now)
                panel.onChoice = { [weak self] in
                    self?.flow.recordVisibleReview(origin: "APPKIT_CONTROL_ACTION")
                    self?.refresh()
                }
                reviewScroll.documentView = panel; reviewPanel = panel
                for control in [panel.confirmButton, panel.rejectButton, panel.cancelButton] {
                    addSubview(control)
                }
                needsLayout = true
                layoutSubtreeIfNeeded()
                scrollReviewToTop()
            } else { reviewPanel?.refresh() }
        } else {
            if let panel = reviewPanel {
                for control in [panel.confirmButton, panel.rejectButton, panel.cancelButton] {
                    control.removeFromSuperview()
                }
            }
            reviewScroll.documentView = nil; reviewPanel = nil
        }
        onStateChanged?()
    }

    func makeWindow() -> NSWindow {
        let window = NSWindow(contentRect: frame, styleMask: [.titled, .closable, .miniaturizable, .resizable],
                              backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.title = "Orchard Release 1 — ZIP検査・人間判断"
        window.contentMinSize = NSSize(width: 640, height: 480)
        window.contentView = self
        needsLayout = true
        layoutSubtreeIfNeeded()
        window.center()
        startReviewRefresh()
        return window
    }

    func state() -> R1ProductState { flow.snapshot() }
    func displayedPlainText() -> String { reviewPanel?.displayedPlainText() ?? status.string }
}

@MainActor
final class R1ProductComposition {
    let root: MacAppBootstrapB7b
    let flow: R1ProductFlow
    let screen: R1ProductScreen
    private init(root: MacAppBootstrapB7b, runtime: R1WorkerRuntime, now: @escaping () -> Date,
                 beforeInspection: (@MainActor () throws -> Void)? = nil) {
        self.root = root
        flow = R1ProductFlow(owner: root.applicationOwner,
                             portFactory: { R1WorkerProcessPort(runtime: runtime) }, now: now,
                             beforeInspection: beforeInspection)
        screen = R1ProductScreen(root: root, flow: flow, now: now)
    }

    // Executes only in an offline Swift harness, never as a signed Orchard app.
    static func offlineProduct(store: PersistentJobsB, metadata: MetadataProbeB,
        accessFactory: @escaping () -> AccessLeaseB, runtime: R1WorkerRuntime,
        now: @escaping () -> Date = Date.init) throws -> R1ProductComposition {
        let root = try MacAppBootstrapB7b.offlineProductQualification(store: store,
            metadata: metadata, accessFactory: accessFactory)
        return R1ProductComposition(root: root, runtime: runtime, now: now)
    }

    // Future native caller must provide fresh exact admission and a separately
    // qualified signed bundle. This factory does not start NSApplication.
    static func nativeCandidate(rootURL: URL, waitingURL: URL, registration: RegistrationJobB,
        sessionID: UUID? = nil, admission: R1ProductNativeAdmission, appBundle: URL,
        now: @escaping () -> Date = Date.init,
        runtime: R1WorkerRuntime? = nil,
        beforeInspection: (@MainActor () throws -> Void)? = nil,
        requestPresentation: @escaping ([JobSnapshotB]) -> Void = { _ in }) throws -> R1ProductComposition {
        try admission.verifyR1ProductScope()
        let root = try MacAppBootstrapB7b.nativeCandidate(root: rootURL, waiting: waitingURL,
            registration: registration, sessionID: sessionID, admission: admission,
            publish: { _ in }, present: requestPresentation)
        guard root.applicationOwner.store.productNativeQualification else { throw BootstrapFaultB7b.wrongEvidenceDriver }
        return R1ProductComposition(root: root, runtime: runtime ?? .a8Bundled(in: appBundle), now: now,
                                    beforeInspection: beforeInspection)
    }

    func bindNativeCallbacks(to application: NSApplication,
                             admission: R1ProductNativeAdmission = HoldR1ProductNativeAdmission()) throws {
        guard root.driver == .nativeCandidate else { throw BootstrapFaultB7b.wrongEvidenceDriver }
        try admission.verifyR1ProductScope()
        try root.bindNativeCallbacks(to: application, admission: admission)
    }
}
