import AppKit

// Standalone offline AppKit receiver. The real Orchard app does not instantiate it.
@MainActor
final class R1ReviewPanel: NSView {
    private let session: R1ReviewSession
    private let now: () -> Date
    private let titleLabel = NSTextField(labelWithString: "Orchard ZIP 検査結果")
    private let subtitleLabel = NSTextField(labelWithString: "固定範囲の静的検査。安全や開封を保証しません。")
    private let statusLabel = NSTextField(labelWithString: "")
    private let footerLabel = NSTextField(labelWithString: "実フォルダ出力・AI引き渡しはG1 Sandboxと安全な展開経路の資格まで禁止")
    private let scroll = NSScrollView()
    private let textView = NSTextView()
    let confirmButton = NSButton(title: "確認して模擬出力", target: nil, action: nil)
    let rejectButton = NSButton(title: "拒否", target: nil, action: nil)
    let cancelButton = NSButton(title: "取消", target: nil, action: nil)
    var onChoice: (() -> Void)?

    init(frame frameRect: NSRect, session: R1ReviewSession, now: @escaping () -> Date) {
        self.session = session
        self.now = now
        super.init(frame: frameRect)
        wantsLayer = true
        titleLabel.frame = NSRect(x: 28, y: 748, width: 900, height: 36)
        titleLabel.font = NSFont.boldSystemFont(ofSize: 27)
        subtitleLabel.frame = NSRect(x: 30, y: 716, width: 900, height: 26)
        subtitleLabel.font = NSFont.systemFont(ofSize: 14)
        statusLabel.frame = NSRect(x: 28, y: 661, width: 904, height: 46)
        statusLabel.font = NSFont.boldSystemFont(ofSize: 19)
        statusLabel.drawsBackground = true
        statusLabel.isBordered = false
        scroll.frame = NSRect(x: 28, y: 173, width: 904, height: 474)
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        textView.frame = NSRect(x: 0, y: 0, width: 884, height: 470)
        textView.isEditable = false
        textView.isSelectable = false
        textView.isRichText = false
        textView.importsGraphics = false
        textView.isAutomaticLinkDetectionEnabled = false
        textView.isAutomaticDataDetectionEnabled = false
        textView.font = NSFont.systemFont(ofSize: 14)
        textView.textColor = NSColor.labelColor
        textView.textContainerInset = NSSize(width: 16, height: 14)
        textView.isHorizontallyResizable = false
        textView.isVerticallyResizable = true
        textView.textContainer?.widthTracksTextView = true
        scroll.documentView = textView
        confirmButton.frame = NSRect(x: 28, y: 111, width: 200, height: 39)
        rejectButton.frame = NSRect(x: 244, y: 111, width: 108, height: 39)
        cancelButton.frame = NSRect(x: 364, y: 111, width: 108, height: 39)
        confirmButton.identifier = NSUserInterfaceItemIdentifier("r1.confirm.mock")
        rejectButton.identifier = NSUserInterfaceItemIdentifier("r1.reject")
        cancelButton.identifier = NSUserInterfaceItemIdentifier("r1.cancel")
        confirmButton.target = self; confirmButton.action = #selector(confirmAction(_:))
        rejectButton.target = self; rejectButton.action = #selector(rejectAction(_:))
        cancelButton.target = self; cancelButton.action = #selector(cancelAction(_:))
        footerLabel.frame = NSRect(x: 30, y: 49, width: 900, height: 45)
        footerLabel.font = NSFont.systemFont(ofSize: 13)
        footerLabel.textColor = NSColor.secondaryLabelColor
        for element in [titleLabel, subtitleLabel, statusLabel, scroll, confirmButton, rejectButton, cancelButton, footerLabel] {
            addSubview(element)
        }
        refresh()
    }
    required init?(coder: NSCoder) { return nil }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()
    }

    func refresh() {
        let reviewNow = now()
        let state = session.snapshot(now: reviewNow)
        let remaining = (state.decision == R1ReviewDecision.awaiting.rawValue ||
                         state.decision == R1ReviewDecision.confirmed.rawValue)
            ? " · 残り \(session.remainingReviewSeconds(now: reviewNow)) 秒" : ""
        statusLabel.stringValue = "\(state.inspectionStatus) / \(state.promptInjection)   ·   \(state.decision)\(remaining)"
        statusLabel.backgroundColor = state.decision == "AWAITING_HUMAN" ? NSColor.systemYellow.withAlphaComponent(0.22) : NSColor.systemRed.withAlphaComponent(0.16)
        textView.string = state.lines.joined(separator: "\n\n")
        confirmButton.isEnabled = state.confirmEnabled
        let choiceOpen = state.decision == "AWAITING_HUMAN" || state.decision == "HUMAN_CONFIRMED_MOCK_ONLY" || state.decision == "HOLD"
        rejectButton.isEnabled = choiceOpen
        cancelButton.isEnabled = choiceOpen
        needsDisplay = true
        textView.needsDisplay = true
    }
    func displayedPlainText() -> String { textView.string }
    func state() -> R1ReviewSnapshot { session.snapshot(now: now()) }

    @objc private func confirmAction(_ sender: NSButton) {
        _ = session.confirm(now: now())
        refresh()
        onChoice?()
    }
    @objc private func rejectAction(_ sender: NSButton) {
        session.reject(now: now())
        refresh()
        onChoice?()
    }
    @objc private func cancelAction(_ sender: NSButton) {
        session.cancel(now: now())
        refresh()
        onChoice?()
    }
}
