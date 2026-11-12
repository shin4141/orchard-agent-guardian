// Ordinary AppKit entry for a human Finder launch. Opening the UI grants no
// authority to inspect or extract a ZIP and reads no AI permission file.
import AppKit

@main
struct OrchardProductMain {
    @MainActor
    static func main() {
        let application = NSApplication.shared
        let delegate = R1HumanProductApplication(application: application)
        application.setActivationPolicy(.regular)
        application.delegate = delegate
        withExtendedLifetime(delegate) {
            application.run()
        }
    }
}
