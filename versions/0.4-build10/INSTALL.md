# First installation

Orchard 0.4 (build10) supports Apple Silicon/macOS26+. It is ad-hoc signed and not notarized by Apple. An app-specific exception is not a safety guarantee.

## Download and expand once

1. Download `Orchard-0.4-build10-release.zip` and `SHA256SUMS` from the project's GitHub Release. Check the filename, trusted source and [checksum](VERIFY.md).
2. Expand that ZIP once. On a Mac, the usual action is to double-click the ZIP.
3. Open the resulting `Orchard-build10` folder. **Orchard.app is directly inside it.** No second application archive needs to be opened.

```text
Orchard-build10/
  Orchard.app
  README.md / README.ja.md
  INSTALL.md / INSTALL.ja.md
  LICENSE / THIRD_PARTY_NOTICES.md
  licenses/
  examples/
```

The README, installation guide and license materials sit beside the app. Keep the license materials with it. Separate Python or Homebrew installation is unnecessary.

## Open Orchard

1. Double-click **Orchard.app**. Avoid running multiple Orchard versions monitoring simultaneously.
2. If the warning says Apple cannot verify the developer or check the app for malware, first check its source and integrity, then go to System Settings → Privacy & Security.
3. Find the blocked Orchard entry and choose **Open Anyway**, labeled 「このまま開く」 in Japanese.

![Orchard's blocked entry in macOS settings with Open Anyway](images/first-launch-blocked.ja.png)

4. Confirm the next app-specific prompt using **Open Anyway** / 「このまま開く」. If macOS requests authentication, the user performs it in the OS dialog; do not send passwords to support.

![Japanese Orchard warning and app-specific confirmation](images/first-launch-open-anyway.ja.png)

These are two crops from one supplied Japanese macOS screenshot: the blocked entry and the confirmation dialog. Original pixels are retained; surrounding information and image metadata are removed. They do not show click completion or post-launch results. Wording can vary with OS version and language. [Apple's instructions](https://support.apple.com/en-us/102445).

There is no need to disable Gatekeeper globally or remove quarantine. Stop on damaged-app, will-damage-your-computer, known-malware or administrator-policy warnings and use [support](SUPPORT.md).

## First inspection

Choose 「ZIPを選んで照合」 and select `examples/benign-notes.zip` in the same extracted folder, then choose 「このZIPを照合」. Read the reference snapshot and results; see the [guide](GUIDE.md). Nonmatches and rule non-detection do not establish safety.

The earlier owner report covers a browser download of the older nested kit, app-specific approval, launch and inspection results. The extraction method was not recorded; Finder use is not asserted. That evidence is separate from Mac acceptance of this single-extraction kit. Static structure, content and signature checks do not establish another-Mac operation or runtime worker Sandbox enforcement.
