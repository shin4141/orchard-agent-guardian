// Product entry composition for a separately admitted native acceptance.
// A9 typechecks this source but does not call prepare or run.
import AppKit
import Foundation
import UniformTypeIdentifiers

// UI lifetime is independent of protected-operation preparation. Human
// startup prepares a fresh session after the window; it never starts work.
@MainActor
final class R1HumanProductApplication: NSObject, NSApplicationDelegate {
    private let application: NSApplication
    private(set) var window: NSWindow?
    private(set) var protectedSession: R1FreshProductSession?
    private var initializationAttempted = false
    private var terminationPending = false
    private var observationMenuItem: NSMenuItem?
    private let status = NSTextField(wrappingLabelWithString:
        "ZIPの検査・展開の準備が整っていません。起動だけではファイルを処理しません。")

    init(application: NSApplication) {
        self.application = application
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu()
        let appItem = NSMenuItem()
        let appMenu = NSMenu(title: "Orchard")
        appMenu.autoenablesItems = false
        let observation = NSMenuItem(title: "動作状態を記録", action: #selector(recordOperationState(_:)), keyEquivalent: "")
        observation.target = self; observation.isEnabled = false
        observationMenuItem = observation; appMenu.addItem(observation)
        appMenu.addItem(.separator())
        let quit = NSMenuItem(title: "Orchardを終了", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = application
        appMenu.addItem(quit); appItem.submenu = appMenu; menu.addItem(appItem)
        application.mainMenu = menu
        showWindow()
        connectOperationSession()
    }

    private func connectOperationSession() {
        guard !initializationAttempted else { return }
        initializationAttempted = true
        var prepared: R1FreshProductSession?
        do {
            let session = try R1HumanOperationSession.prepare()
            prepared = session
            try installProtectedSession(session)
        } catch {
            prepared?.humanOperations?.shutdown { _ in }
            application.delegate = self
            status.stringValue = "操作の準備を確認できませんでした。検査・展開を停止し、記録を保持しています。"
            FileHandle.standardError.write(Data(("Orchard session HOLD: " + String(describing: error) + "\n").utf8))
        }
    }

    private func showWindow() {
        if window == nil {
            let content = NSView(frame: NSRect(x: 0, y: 0, width: 980, height: 600))
            let title = NSTextField(labelWithString: "Orchard — ZIP検査・人間判断")
            title.font = NSFont.boldSystemFont(ofSize: 25)
            title.frame = NSRect(x: 28, y: 510, width: 920, height: 42)
            let detail = NSTextField(wrappingLabelWithString:
                "検査結果・根拠・判断できない点を確認してから、別の操作で限定展開します。")
            detail.frame = NSRect(x: 30, y: 425, width: 900, height: 60)
            status.frame = NSRect(x: 30, y: 315, width: 900, height: 80)
            let inspect = NSButton(title: "ZIPを検査", target: nil, action: nil)
            let extract = NSButton(title: "確認したZIPを限定展開", target: nil, action: nil)
            inspect.frame = NSRect(x: 30, y: 230, width: 210, height: 36)
            extract.frame = NSRect(x: 260, y: 230, width: 270, height: 36)
            inspect.isEnabled = false
            extract.isEnabled = false
            for view in [title, detail, status, inspect, extract] { content.addSubview(view) }
            let created = NSWindow(contentRect: content.frame,
                styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            created.isReleasedWhenClosed = false
            created.title = "Orchard"
            created.contentView = content
            created.center()
            window = created
        }
        window?.makeKeyAndOrderFront(nil)
        application.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if let session = protectedSession, !session.entry.composition.flow.isInspecting {
            _ = session.entry.composition.root.applicationDelegate.reopenProjection()
        }
        showWindow()
        return false
    }

    func application(_ sender: NSApplication, open urls: [URL]) {
        if let session = protectedSession, session.entry.composition.flow.canAcceptInput,
           !terminationPending {
            session.entry.composition.root.applicationDelegate.application(sender, open: urls)
            showWindow()
            return
        }
        // Unconnected/busy/closing delivery cannot stage, inspect or replay.
        for original in urls {
            let access = AppKitImplicitLeaseB7b()
            if access.begin(original) { access.end() }
        }
        showWindow()
        if protectedSession == nil {
            status.stringValue = "ファイルは検査していません。検査・展開の準備が整うまで操作できません。"
        }
        let reason = terminationPending ? "NATIVE_INPUT_TERMINATING" :
            (protectedSession == nil ? "NATIVE_INPUT_SESSION_UNAVAILABLE" : "NATIVE_INPUT_FLOW_NOT_READY")
        if let session = protectedSession, let operations = session.humanOperations {
            do { try operations.resources.ledger.record("OPEN_URLS_HELD",
                ["reason": reason, "count": urls.count, "replayed": false, "staged": false]) }
            catch {
                session.entry.composition.flow.holdOperations("INPUT_EVIDENCE_WRITE_FAILED")
                FileHandle.standardError.write(Data("Orchard input HOLD: INPUT_EVIDENCE_WRITE_FAILED\n".utf8))
            }
        } else {
            FileHandle.standardError.write(Data(("Orchard input HOLD: " + reason + "\n").utf8))
        }
    }

    // Keep this one application delegate as the human lifetime owner; forward
    // operation callbacks to the existing B8 lifecycle after qualification.
    func installProtectedSession(_ session: R1FreshProductSession) throws {
        guard protectedSession == nil, session.entry.application === application,
              session.entry.composition.root.driver == .nativeCandidate,
              session.entry.composition.root.applicationOwner.store.productNativeQualification,
              let operations = session.humanOperations else {
            throw R1FreshProductFault.configuration
        }
        try operations.resources.ledger.record("OPERATION_WINDOW_ATTACHED", ["worker_starts": 0,
            "inspection_requires_explicit_action": true, "extraction_requires_separate_action": true])
        protectedSession = session
        let previousWindow = window
        window = session.entry.window
        application.delegate = self
        session.entry.composition.screen.requestZIPSelection = { [weak self] in self?.chooseZIP() }
        session.entry.composition.screen.refresh()
        observationMenuItem?.isEnabled = true
        previousWindow?.close()
        window?.makeKeyAndOrderFront(nil)
        application.activate(ignoringOtherApps: true)
    }

    private func chooseZIP() {
        guard let session = protectedSession, session.entry.composition.flow.canAcceptInput,
              !terminationPending, let window else { return }
        let panel = NSOpenPanel()
        panel.resolvesAliases = false
        panel.canChooseDirectories = false; panel.canChooseFiles = true
        panel.allowsMultipleSelection = false; panel.allowedContentTypes = [.zip]
        panel.prompt = "選択"; panel.message = "検査するZIPを選択してください。選択だけでは検査・展開しません。"
        panel.beginSheetModal(for: window) { [weak self] response in
            guard response == .OK else { return }
            if let self { self.application(self.application, open: panel.urls) }
            else { for original in panel.urls { original.stopAccessingSecurityScopedResource() } }
        }
    }

    @objc private func recordOperationState(_ sender: NSMenuItem) {
        guard !terminationPending, let session = protectedSession,
              session.entry.composition.flow.canAcceptInput else { return }
        observationMenuItem?.isEnabled = false
        session.humanOperations?.recordSandboxObservation()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let operations = protectedSession?.humanOperations else { return .terminateNow }
        if terminationPending { return .terminateLater }
        terminationPending = true
        DispatchQueue.main.async { [weak self] in
            operations.shutdown { closed in
                guard let self else { return }
                self.terminationPending = false
                self.application.reply(toApplicationShouldTerminate: closed)
            }
        }
        return .terminateLater
    }
}

@MainActor
private final class R1ProductWindowPresentation {
    weak var window: NSWindow?
    func show() {
        window?.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }
}

@MainActor
final class R1ProductAppEntry {
    let composition: R1ProductComposition
    let application: NSApplication
    let window: NSWindow

    private init(composition: R1ProductComposition, application: NSApplication, window: NSWindow) {
        self.composition = composition; self.application = application; self.window = window
    }

    static func validateV7Registration(rootURL: URL, registration: RegistrationJobB) throws {
        let raw = try readJobFileB(rootURL.appendingPathComponent("anchor.json"), cap: 8192)
        let anchor = try decodeJobB(StoreAnchorJobB.self, raw)
        guard anchor.version == 7, anchor.scope == JobStoreScopeB.r1ProductNative,
              anchor.storeID == registration.storeID, anchor.ownerID == registration.ownerID,
              hash54(raw) == registration.anchorSHA256 else {
            throw BootstrapFaultB7b.wrongEvidenceDriver
        }
    }

    static func prepare(rootURL: URL, waitingURL: URL, registration: RegistrationJobB,
                        sessionID: UUID? = nil, appBundle: URL,
                        admission: R1ProductNativeAdmission,
                        runtime: R1WorkerRuntime? = nil,
                        beforeInspection: (@MainActor () throws -> Void)? = nil) throws -> R1ProductAppEntry {
        try admission.verifyR1ProductScope()
        try validateV7Registration(rootURL: rootURL, registration: registration)
        let selectedRuntime = runtime ?? R1WorkerRuntime.a8Bundled(in: appBundle)
        try selectedRuntime.validateBeforeSpawn()
        let presentation = R1ProductWindowPresentation()
        let composition = try R1ProductComposition.nativeCandidate(rootURL: rootURL,
            waitingURL: waitingURL, registration: registration, sessionID: sessionID,
            admission: admission,
            appBundle: appBundle, runtime: selectedRuntime, beforeInspection: beforeInspection,
            requestPresentation: { _ in presentation.show() })
        // The OS may deliver a file-open event as soon as the delegate binds.
        // Hold every native URL until the current session's admission is installed.
        composition.root.nativeInputAdmission = { _ in
            throw NativeInputRejectionB7b(stage: .provider, code: .providerNotReady)
        }
        let application = NSApplication.shared
        try composition.bindNativeCallbacks(to: application, admission: admission)
        let window = composition.screen.makeWindow()
        presentation.window = window
        return R1ProductAppEntry(composition: composition, application: application, window: window)
    }

    func runAfterSeparateNativeGO() {
        window.makeKeyAndOrderFront(nil)
        application.activate(ignoringOtherApps: true)
        application.run()
    }
}
