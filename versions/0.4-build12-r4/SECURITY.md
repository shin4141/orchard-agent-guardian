# Security / セキュリティ

The app verifies its Bundle ID, manifests, pinned runtime/worker/database hashes and package inventories.
ZIP bytes are passed through an owned file descriptor to a bounded one-shot worker. The inspection helper has App Sandbox enabled and no file/network access entitlements.
The GUI host and Sentinel are not a general-purpose sandbox for agents or the rest of your Mac.
This release has a verified Developer ID signature and an Apple notarization ticket. The published checksum verifies the identity of the downloaded ZIP.

Bundle ID、manifest、runtime・worker・DBのSHAと同梱物の検証を維持しています。
検査workerの実行境界と、GUI/Sentinelの権限は別です。Mac全体やAIエージェントを隔離するものではありません。
この版にはDeveloper ID署名とApple公証チケットが付属します。配布チェックサムは、ダウンロードしたZIPの同一性を照合するために使用します。

## Report a concern / 問題の連絡

Use the existing [project Issues](https://github.com/shin4141/orchard-agent-guardian/issues) for a **non-sensitive request to contact the maintainer**.
State the app version, OS version and warning/result category. Do not post exploit details, credentials, project text, malware samples, real SHA lists or the database.
For a confidential matter, ask for a private channel first. No dedicated private-report endpoint or response-time guarantee is claimed here.
Data providers should use the existing written permission correspondence for removal or withdrawal notices.

一般窓口は既存のIssuesです。機密を含まない連絡依頼から始めてください。非公開の脆弱性受付機能が有効であるとの保証はしません。
データ提供者の削除・撤回は既存の書面連絡経路で受け付け、[対応手順](SUPPORT.md)に従います。

Unexpected damaged/malware warnings, checksum mismatches, unknown integrity failures or unexplained monitoring state should stop the attempted workflow.
Do not work around them by disabling macOS protection, deleting quarantine, editing manifests/databases or re-signing the application.
Keep a non-sensitive description for support. The frozen bundle must be retired and replaced through a separately approved candidate if its data or integrity needs correction.
