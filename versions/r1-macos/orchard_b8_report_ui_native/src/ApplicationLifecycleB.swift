// One AppKit delegate; no NSApplication instance, run loop, or window is created here.
import AppKit

@MainActor
final class ApplicationLifecycleJobsB: NSObject, NSApplicationDelegate {
    let applicationOwner: ApplicationJobsB
    let dock: DockZipDelegateB
    let projection: WindowProjectionJobsB
    let publish: (ApplicationViewJobsB) -> Void
    let requestPresentation: ([JobSnapshotB]) -> Void
    private(set) var quitState = "NOT_REQUESTED"
    private(set) var quitError: String?
    init(applicationOwner: ApplicationJobsB, dock: DockZipDelegateB, projection: WindowProjectionJobsB,
         publish: @escaping (ApplicationViewJobsB) -> Void, requestPresentation: @escaping ([JobSnapshotB]) -> Void) {
        self.applicationOwner = applicationOwner; self.dock = dock; self.projection = projection
        self.publish = publish; self.requestPresentation = requestPresentation
    }
    var terminateAfterLastWindowClosed: Bool { false }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { terminateAfterLastWindowClosed }
    func application(_ application: NSApplication, open urls: [URL]) { _ = dock.receivedAppKitURLs(urls) }
    func reopenProjection() -> [JobSnapshotB] {
        let states = projection.windowReopened(); publish(applicationOwner.viewState()); requestPresentation(states)
        return states // Presentation request is not a native visibility ACK or an inspection result.
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag { _ = reopenProjection() }
        return false
    }
    func prepareQuit() -> Bool {
        if quitState == "QUIT_ACK_STORE_CLOSED" { return true }
        if quitState == "HOLD_QUIT_UNCONFIRMED" { return false }
        do {
            try applicationOwner.applicationQuit(); quitState = "QUIT_ACK_STORE_CLOSED"
            publish(applicationOwner.viewState()); return true
        } catch {
            quitState = "HOLD_QUIT_UNCONFIRMED"; quitError = String(describing: error)
            publish(applicationOwner.viewState()); return false
        }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        prepareQuit() ? .terminateNow : .terminateCancel
    }
    func applicationWillTerminate(_ notification: Notification) {
        _ = prepareQuit()
        try? ProcessBootstrapOwnerB7b.releaseClosedOwner(applicationOwner)
    }
}

@MainActor
final class WindowLifecycleJobsB: NSObject, NSWindowDelegate {
    let projection: WindowProjectionJobsB
    init(projection: WindowProjectionJobsB) { self.projection = projection }
    func closeProjection() { projection.windowClosed() }
    func windowWillClose(_ notification: Notification) { closeProjection() }
}
