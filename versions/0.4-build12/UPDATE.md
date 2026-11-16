# Update and registration continuity — build12

Read [acceptance status](RELEASE_NOTES.md) first. Adoption with zero and one pending change and subsequent change review were observed with disposable r2-equivalent state. Real user registrations were not switched for testing. Retain the old application and state; updating is not a reason to delete them.

1. Stop monitoring in the older Orchard and quit it normally. Pending changes can remain unapproved.
2. Build12 uses `~/Library/Application Support/Orchard/registration.json` as a version-independent pointer. A compatible public r2 registration in `Private100KCandidate7/registration.json` is validated and referenced at its existing `state_dir`. Baseline, pending evidence and approval history are neither moved nor deleted nor auto-approved.
3. A registration found only under build11's `Private300KCandidate11` requires explicit confirmation via 「別の登録を確認」. Review the folder and pending count before adopting it. The two registrations are never merged, and invalid r2 state is not silently bypassed in favor of build11.
4. Verify the folder and pending count. Monitoring remains stopped until you manually choose 「監視を開始」. No login startup is added.

An active older monitor lease, busy state, invalid JSON, root mismatch, missing evidence or interrupted acceptance produces an explained hold, not a silent unregistered reset. Finish older activity and use 「登録を再確認」. Retain damaged files and ask [support](SUPPORT.md); deleting them can lose pending evidence.

The new pointer may still reference state inside the old r2 or confirmed build11 directory. Do not delete it because its name looks old. See [rollback](ROLLBACK.md) and [removal](UNINSTALL.md).

## If registration verification times out

Existing registration, baseline, pending changes and approval history are retained. Registration verification is held, but ZIP inspection remains available through 「ZIPを選んで照合」. ZIP inspection's own integrity failures or inability to inspect can still hold that separate workflow.

Choose 「登録を再確認」 (recheck registration), or quit Orchard normally and restart it. Do not delete or initialize registration/state files. If it recurs, report the phase name in parentheses in the timeout message (for example `READER_IMPORT` or `START_UNKNOWN`), the build number and macOS version through [support](SUPPORT.md). Do not attach registration JSON, watched text/diffs or secrets to a public issue.

The cause of earlier timeouts remains unconfirmed. Rechecking or restarting is not guaranteed to resolve it.
