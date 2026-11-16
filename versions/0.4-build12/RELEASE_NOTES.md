# Orchard 0.4 — build12

Build12 retains the real 300,000-value subset from build11 (all previous 100,000 plus 200,000 additions), age-advisory matching and the large red instruction warning. It removes internal candidate labels from the main UI and adds a version-independent registration pointer with validated r2 adoption and explicit build11-only selection. Existing state is referenced, not migrated. Monitoring still starts manually. Detector rules, worker machine-code instructions, runtime dependency bytes and the 300k database remain unchanged from build11. Changed host/resources receive fresh ad-hoc seals; there is no Apple notarization.

## Acceptance status / 検証状況

- Offline continuity tests: 21 PASS, including pending 0/1, old formats, exact state-byte preservation on adoption, active-lease refusal, corruption, explicit selection and post-adoption audit/review without acceptance. These use synthetic state and trusted host Python, not the bundled runtime's GUI.
- Native update acceptance: **PASS for the limited disposable-state cases**. The same fixed build12 adopted r2-equivalent registrations with zero and one pending change while preserving baseline/pending/history bytes and remaining stopped. Manual monitoring, app status, MD change notification, Japanese explanation, diff, cancel and stop retained one unapproved change. A malformed registration produced an explained hold without initialization. A single harmless instruction-test ZIP returned the 300k reference, normal nonmatch, age advisory and large red warning. Internal lookups are not a malware detection rate.
- Build12 first-use GUI paths remain untested: the initial unregistered display, and registering/saving a new project. The three existing-registration GUI cases do not validate these paths. build12の初回利用時の未登録表示、新規プロジェクト登録・保存の実GUI試験は未実施です。既存登録の引き継ぎ等3ケースのPASSとは区別します。
- Static compilation, deep/strict ad-hoc signature verification and ZIP content/mode/symlink read-back: PASS. State and processes used in these tests were disposable; existing r2 registrations were not modified.
- Internet first installation, another Mac, runtime worker Sandbox enforcement and an unmodified OS menu-bar image for build12: unverified.

同一build12の使い捨て状態による限定受入を確認しました。先行する2つの試験artifactでは登録helper時間切れが発生し、原因は確定していません。この固定artifactの3ケースでは再現していませんが、すべてのMacでの成功を保証しません。登録検証の時間切れは引き続き「未登録」へ初期化せず理由付き保留になります。既存r2は保持し、取得時刻の書換え・追加SHA取得・自動監視開始は行っていません。

See [update](UPDATE.md), [rollback](ROLLBACK.md), [data sources](DATA_SOURCES.md), [licenses](THIRD_PARTY_NOTICES.md).
