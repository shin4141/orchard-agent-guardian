import Foundation
import CryptoKit
import Darwin

// Integrity check for the exact OFF-gated test package. The outer code signature
// seals this manifest. Ad-hoc signing does not authenticate a publisher or resist
// a same-UID attacker who can replace and re-sign the entire application.
struct SentinelRuntime {
    let python: String
    let detector: String
    let residency: String
    let continuity: String
    let manifestSHA256: String

    static let pythonRelative = "Contents/MacOS/OrchardPython"
    private static let frameworkRelative = "Contents/Frameworks/Python.framework"

    private static func digest(_ file: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        var hash = SHA256()
        while let data = try handle.read(upToCount: 1_048_576), !data.isEmpty { hash.update(data: data) }
        return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func invalid() -> NSError { NSError(domain: "SentinelRuntimeIntegrity", code: 78) }

    static func load(_ app: URL = Bundle.main.bundleURL) throws -> SentinelRuntime {
        let app = app.standardizedFileURL
        guard app.pathExtension == "app", app.resolvingSymlinksInPath() == app,
              Bundle(url: app)?.bundleIdentifier == SentinelResidencyBuild.mainID else { throw invalid() }
        let manifestURL = app.appendingPathComponent("Contents/Resources/RuntimeManifest.json")
        let manifestFD = open(manifestURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard manifestFD >= 0 else { throw invalid() }
        defer { _ = close(manifestFD) }
        var statbuf = stat()
        guard fstat(manifestFD, &statbuf) == 0, statbuf.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              statbuf.st_size > 0, statbuf.st_size <= 524_288 else { throw invalid() }
        let handle = FileHandle(fileDescriptor: manifestFD, closeOnDealloc: false)
        let bytes = try handle.read(upToCount: 524_289) ?? Data()
        guard bytes.count <= 524_288,
              let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              object["version"] as? Int == 1,
              object["activation_allowed"] as? Bool == false,
              object["signing"] as? String == "ADHOC_INTEGRITY_ONLY",
              object["python"] as? String == pythonRelative,
              object["runtime_root"] as? String == frameworkRelative,
              let files = object["files"] as? [[String: Any]], !files.isEmpty, files.count <= 512 else { throw invalid() }
        var expected = Set<String>()
        for entry in files {
            guard let relative = entry["path"] as? String, relative.utf8.count <= 1_024,
                  !relative.hasPrefix("/"), !relative.split(separator: "/", omittingEmptySubsequences: false)
                    .contains(where: { $0 == "." || $0 == ".." || $0.isEmpty }),
                  relative.hasPrefix(frameworkRelative + "/") ||
                    relative == pythonRelative ||
                    relative == "Contents/Resources/sentinel.py" || relative == "Contents/Resources/residency.py" || relative == "Contents/Resources/registration_continuity.py",
                  expected.insert(relative).inserted else { throw invalid() }
            let url = app.appendingPathComponent(relative)
            guard url.resolvingSymlinksInPath().path.hasPrefix(app.path + "/"),
                  lstat(url.path, &statbuf) == 0 else { throw invalid() }
            if let target = entry["symlink"] as? String {
                guard statbuf.st_mode & mode_t(S_IFMT) == mode_t(S_IFLNK), !target.hasPrefix("/"),
                      try FileManager.default.destinationOfSymbolicLink(atPath: url.path) == target else { throw invalid() }
            } else {
                guard statbuf.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                      let size = entry["size"] as? Int64, size >= 0, size <= 134_217_728,
                      statbuf.st_size == size, let sha = entry["sha256"] as? String,
                      sha.count == 64, sha.allSatisfy({ $0.isHexDigit && !$0.isUppercase }),
                      try digest(url) == sha else { throw invalid() }
            }
        }
        let required: Set<String> = [pythonRelative, frameworkRelative + "/Versions/3.14/Python",
            frameworkRelative + "/Versions/3.14/Resources/python314.zip",
            "Contents/Resources/sentinel.py", "Contents/Resources/residency.py", "Contents/Resources/registration_continuity.py"]
        guard required.isSubset(of: expected) else { throw invalid() }
        let actual = Set(try inventoryPaths(in: app.appendingPathComponent(frameworkRelative))
            .map { frameworkRelative + "/" + $0 })
        guard actual == expected.filter({ $0.hasPrefix(frameworkRelative + "/") }),
              FileManager.default.isExecutableFile(atPath: app.appendingPathComponent(pythonRelative).path) else { throw invalid() }
        let manifestHash = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        return SentinelRuntime(python: try physicalPath(app.appendingPathComponent(pythonRelative), inside: app),
            detector: try physicalPath(app.appendingPathComponent("Contents/Resources/sentinel.py"), inside: app),
            residency: try physicalPath(app.appendingPathComponent("Contents/Resources/residency.py"), inside: app),
            continuity: try physicalPath(app.appendingPathComponent("Contents/Resources/registration_continuity.py"), inside: app),
            manifestSHA256: manifestHash)
    }

    // POSIX child identity and Python's no-symlink-parent checks use realpath,
    // while Foundation standardizes /private/var to /var. Convert only files
    // already admitted by the bundle manifest, keeping root containment and
    // the exact device/inode. User-selected project and ZIP paths do not use it.
    static func physicalPath(_ file: URL, inside directory: URL) throws -> String {
        let root = directory.standardizedFileURL
        let entry = file.standardizedFileURL
        guard root.isFileURL, root.resolvingSymlinksInPath() == root,
              entry.path.hasPrefix(root.path + "/"),
              entry.resolvingSymlinksInPath().path.hasPrefix(root.path + "/") else { throw invalid() }
        var before = stat(), after = stat()
        guard lstat(entry.path, &before) == 0,
              before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), before.st_nlink == 1,
              let rootPointer = realpath(root.path, nil) else { throw invalid() }
        defer { free(rootPointer) }
        guard let filePointer = realpath(entry.path, nil) else { throw invalid() }
        defer { free(filePointer) }
        let physical = String(cString: filePointer)
        guard physical.hasPrefix(String(cString: rootPointer) + "/"),
              lstat(physical, &after) == 0,
              after.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG), after.st_nlink == 1,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw invalid() }
        return physical
    }


    // DirectoryEnumerator URLs can use /private/var while standardized bundle
    // URLs use /var. Relative filesystem names are independent of that alias
    // and of App Translocation's randomized mount path. Keep symlink names;
    // resolving them before inventory comparison would hide manifest entries.
    static func inventoryPaths(in directory: URL) throws -> Set<String> {
        let root = directory.standardizedFileURL
        var info = stat()
        guard root.isFileURL, lstat(root.path, &info) == 0,
              info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
              let enumeration = FileManager.default.enumerator(atPath: root.path) else { throw invalid() }
        let resolvedRoot = root.resolvingSymlinksInPath().path + "/"
        var actual = Set<String>()
        while let value = enumeration.nextObject() {
            guard let relative = value as? String, !relative.hasPrefix("/"),
                  relative.utf8.count <= 4096,
                  !relative.split(separator: "/", omittingEmptySubsequences: false)
                    .contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) else { throw invalid() }
            let file = root.appendingPathComponent(relative)
            guard file.resolvingSymlinksInPath().path.hasPrefix(resolvedRoot),
                  lstat(file.path, &info) == 0 else { throw invalid() }
            let kind = info.st_mode & mode_t(S_IFMT)
            if kind != mode_t(S_IFDIR) {
                guard actual.insert(relative).inserted, actual.count <= 512 else { throw invalid() }
            }
        }
        return actual
    }

    static func validates(python: String, script: String) -> Bool {
        var app = URL(fileURLWithPath: script)
        for _ in 0..<3 { app.deleteLastPathComponent() }
        guard let runtime = try? load(app) else { return false }
        return python == runtime.python && (script == runtime.detector || script == runtime.residency || script == runtime.continuity)
    }

    static let environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C", "TMPDIR": NSTemporaryDirectory()]
}
