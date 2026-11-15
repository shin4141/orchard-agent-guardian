# Features and limits / 機能と限界

| Area / 項目 | Implemented / 実装済み | Limit / 限界 |
| --- | --- | --- |
| ZIP | Bounded metadata/text inspection and SHA matching / 有限上限の構造・文書検査とSHA照合 | 8 MiB input, 128 entries, 2 MiB declared per member, 8 MiB aggregate, 100× declared ratio; unsupported or incomplete input is held |
| SHA data | 100,000 unique SHA-256 values / 限定10万件 | No samples, complete corpus, recency ranking or broad detection guarantee / 検体なし・全件や最新順ではない |
| Snapshot age | Source/retrieval dates and age are reference information / 日時・経過時間を表示 | Age alone never blocks stored-snapshot matches/nonmatches; update failure/invalid time still hold / 経過時間のみでは保留しない |
| Instruction checks | Fixed rules over allowlisted UTF-8 documentation / 選択文書への固定規則 | Paraphrases, unsupported languages, obfuscation and other content can evade checks / 言い換え・難読化等に限界 |
| Sentinel | Poll selected instruction filenames recursively / 特定名のファイルを監視 | AGENTS.md, AGENTS.override.md, CLAUDE.md, CLAUDE.local.md, GEMINI.md; skipped directories and size/count bounds apply |
| Review | Local Japanese rules, text/diff/hash review, explicit approval / 日本語規則・差分・明示承認 | Meaning can be unknown; approval is not a safety decision / 意味不明を残す・安全判断ではない |
| Evidence | Pending changes survive stopping/restarting / 未確認保持 | Local files can contain sensitive project text; deletion is explicit / ローカル証拠に機密原文を含み得る |
| Monitoring | Healthy/pending/stopped/unknown are distinguished / 状態を区別 | Polling can miss transient changes; no monitoring guarantee while stopped or exited / 短時間変化や停止中は保証しない |

Selected instruction text has additional bounds (up to 8 documents, 64 KiB each, 256 KiB total). SHA work and text work remain distinct.
Sentinel skips directories such as `.git`, `.venv`, `node_modules`, `vendor`, `build`, `dist`, `.tox` and `__pycache__`.
Its file/state/registration bounds can cause an unknown or rejected registration rather than complete monitoring.

This is not a general antivirus, AI-origin tracker, endpoint write blocker or OS sandbox for AI agents.
It does not establish which agent read a file, prevent all AI writes, automatically approve changes, restore overwritten files, open/extract ZIP contents to a chosen folder, or run archive members.
ZIP bytes and bounded decompression are handled in memory or an anonymous owned input copy; no archive member is installed or executed.

一般的なウイルス対策、AI起点の追跡、書込み防止、AIのOS隔離を提供する製品ではありません。
未一致、規則未検出、監視中、自己確認PASSのいずれも、開封・実行・信頼の許可にはなりません。
build9のZIP結果3状態とbuild10変更UIの限定受入は、それぞれの旧artifactの証拠として保持します。本人は旧二重ZIPのブラウザ取得現物で個別承認・起動・検査結果表示を確認しました。展開操作の方法は未記録です。単層キットの静的な内容・権限・署名一致と、新しいMac初回導入受入を区別します。別Mac・新規user・実行時worker Sandbox・新しいOSメニューバー証拠へPASSを転記しません。

Automatic updates and login-item activation are OFF. There is no in-app data replacement or removal-request synchronization in this fixed build.
No clock, database timestamp or policy changes are part of installation or use.
