# Privacy / プライバシー

ZIP inspection and Sentinel's implemented workflows run locally. They do not upload selected ZIPs, file contents or their hashes to a threat-intelligence service or AI service.
There is no configured analytics, automatic update, sample submission, cloud synchronization or login-startup registration in build10.
macOS may make its own Gatekeeper/security network checks; those are separate from Orchard's workflows. [Apple's description](https://support.apple.com/en-us/102445).

ZIP照合・Sentinelの処理はローカルです。検査対象、原文、SHAを外部やAIへ送る処理はありません。
自動取得、解析telemetry、検体送信、クラウド同期、ログイン時起動は有効化していません。
OS自身のセキュリティ確認通信とは区別してください。

## Stored information / 保存する情報

- The selected registration root and local monitoring state / 登録したフォルダのパス。
- Baseline instruction text and hashes, detected changes, pending originals/diffs, and approval evidence / 信頼基準・SHA・検知変更・未確認の原文や差分・承認記録。
- The bundled bounded hash database and credential-free source metadata / 同梱の限定倉庫と認証情報を含まない出典metadata。

Sentinel state is under `~/Library/Application Support/Orchard/Private100KCandidate7/`.
It is protected by local filesystem access controls, not an application-level encrypted vault.
Another program running with sufficient access to your user account may access these files.
OS-managed app preferences, dialog history and sandbox/container metadata may also exist.

監視証拠にはプロジェクトの機密が含まれ得ます。アプリ独自の暗号化保管庫ではないため、同じuser権限等で読める場合があります。
問い合わせに登録JSON、原文、差分、DB、SHA一覧をそのまま添付しないでください。

State is retained until explicitly removed. Quitting does not erase pending evidence.
[Uninstall instructions](UNINSTALL.md) identify the candidate-specific folder; they do not delete a registered project or reset system security history.
Browser downloads and support systems have their own privacy policies. Opening the linked websites is a separate user action.
