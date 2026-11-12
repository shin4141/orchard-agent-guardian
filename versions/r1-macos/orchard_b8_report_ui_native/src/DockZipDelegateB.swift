// Reused Dock entry component. ApplicationLifecycleJobsB is the sole NSApplicationDelegate.
import AppKit

@MainActor
final class DockZipDelegateB: NSObject {
    private let route: ([URL], IngressOriginB7b) -> IngressBatchB7b
    init(route: @escaping ([URL], IngressOriginB7b) -> IngressBatchB7b) { self.route = route }
    func receivedAppKitURLs(_ urls: [URL]) -> IngressBatchB7b { route(urls, .appKitImplicit) }
    func receivedSyntheticCallback(_ urls: [URL]) -> IngressBatchB7b { route(urls, .syntheticCallback) }
}
