# Stop and uninstall / 停止・削除

1. In Orchard, choose **監視を停止** and wait for **停止中**. Pending evidence remains.
2. Quit Orchard with ⌘Q.
3. Move the extracted Orchard.app to Trash in Finder. If you are removing the whole distribution, also remove the はじめに・説明書 folder and downloaded ZIP when no longer needed. While retaining or redistributing the app, keep its complete guides/license folder with it.
4. Only if you also intend to remove registration, baseline, pending text/diffs and approval evidence, use Finder → Go → Go to Folder and open `~/Library/Application Support/Orchard/`. Move **Private100KCandidate7 only** to Trash. Keep needed evidence first.

「監視を停止」→停止表示→⌘Qの順です。停止・終了だけでは未確認証拠を消しません。
build7/build8/build9/build10は同じ候補用保存先です。このフォルダの削除はこれらの版の登録・証拠に影響するため、必要な記録を先に保持してください。
登録も削除する場合は `Private100KCandidate7` だけを対象にします。他版の登録や、監視対象のプロジェクト本体は削除しません。
この候補はログイン項目を登録していないため、その解除手順はありません。

These steps do not erase OS-managed preferences, app-specific approval history, LaunchServices records, containers, system logs or backups.
They do not remotely delete copies held elsewhere. Provider withdrawal/removal requires the separate [maintainer procedure](SUPPORT.md).
Do not reset global security settings or delete unrelated Orchard data to uninstall this candidate.
