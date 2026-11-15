# Orchard 0.4 — Release 1 (build10)

Release 1 finalizes the public-facing UI of GUI-tested build9.

- Window/title: Orchard 🍎. Visible product version: Orchard 0.4. Unpublished/private build labels are removed from the normal UI.
- The 25-hour and failed-update simulation buttons are absent from the public UI. Internal verification modes remain unchanged.
- The large 24pt bold red instruction warning remains above SHA results; file/line evidence and SHA/source/timestamp details remain available.
- SHA matching, the same stored 100,000 entries, age-advisory policy, detection rules, worker/runtime/manifests, Sentinel, pending evidence and manual approval boundary are unchanged.
- Source and guides explain local folders without GitHub, registration with no supported MD yet, added-file detection while monitoring, one-folder registration and manual start without continuous-monitoring guarantees.

旧build9の原ZIP・キット・証拠を保持してbuild10を別生成しました。タイトルと一般向け表示、検証ボタンの露出だけを整理しています。
コード・データの許諾は従来どおり。無料・非商用OSS、abuse.chの条件付きsubset同梱、帰属、学習不使用、削除・撤回対応を維持します。

Validation: static Swift compilation, deep/strict ad-hoc verification and exact same-ZIP inventory read-back passed.
Build10 passed changed-UI acceptance on macOS26.6.2: Orchard 🍎 / Orchard 0.4, product labels without private-build wording or simulation buttons, the retained large red warning, and normal stored-snapshot SHA results for detected-text and benign ZIPs. One GUI launch, two ZIP jobs, normal GUI quit and temporary-policy restoration completed. Build9 evidence remains scoped to that earlier artifact; no full suite or Sentinel retest was performed.

Distribution UX update: expand `Orchard-0.4-build10-release.zip` once to find Orchard.app beside the README, INSTALL and license materials. The app bundle, database, signed code, Sentinel and detection rules are unchanged. Existing file modes and symlink targets are preserved; no re-signing occurs. The guides show privacy-cropped blocked-entry and app-specific confirmation views.

Correction: the earlier owner report confirms a browser-downloaded older kit, app-specific approval, launch and inspection results. It does not record the extraction method; prior Finder-use assertions are withdrawn. The old download checksum, new kit's static structure/content/signature checks and new kit's Mac acceptance are separate evidence. No runtime Sandbox or another-Mac PASS follows from this repackaging.

Signing remains ad-hoc, without notarization. App-specific approval is not a safety guarantee. Gatekeeper-wide disabling or quarantine removal is unnecessary.
[Limits](LIMITS.md) · [Installation](INSTALL.md) · [Data conditions](DATA_SOURCES.md) · [Verification](VERIFY.md)
