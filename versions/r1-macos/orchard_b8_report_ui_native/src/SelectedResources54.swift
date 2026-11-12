// Only a host-selected pinned seed is copied. No guest path or recursive delete.
import Foundation
import CryptoKit
import Darwin

struct FileIdentity54 {
    let device: dev_t
    let inode: ino_t
    let mode: mode_t
    let uid: uid_t
    let links: nlink_t
    let size: off_t
    let modified: timespec
    let changed: timespec
    init(_ value: stat) {
        device = value.st_dev; inode = value.st_ino; mode = value.st_mode
        uid = value.st_uid; links = value.st_nlink; size = value.st_size
        modified = value.st_mtimespec; changed = value.st_ctimespec
    }
    func sameObject(_ value: stat) -> Bool {
        device == value.st_dev && inode == value.st_ino && mode == value.st_mode
            && uid == value.st_uid && links == value.st_nlink
    }
    func unchanged(_ value: stat) -> Bool {
        sameObject(value) && size == value.st_size
            && modified.tv_sec == value.st_mtimespec.tv_sec && modified.tv_nsec == value.st_mtimespec.tv_nsec
            && changed.tv_sec == value.st_ctimespec.tv_sec && changed.tv_nsec == value.st_ctimespec.tv_nsec
    }
}

func hash54(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

final class PinnedRead54 {
    let url: URL
    let expectedSize: Int64
    let expectedSHA256: String
    private var descriptor: Int32 = -1
    private var identity: FileIdentity54?
    private var closeAttempted = false
    private var checkpoint: () throws -> Void = {}

    // B-only selected-FD entry. The original copy/hash/identity loop is reused.
    // Source Resources54.swift and A's compiled objects remain unchanged.
    func openAndPin(selectedFD: Int32, selectedIdentity: FileIdentity54,
                    checkpoint: @escaping () throws -> Void) throws {
        guard descriptor == -1 && !closeAttempted,
              fcntl(selectedFD, F_GETFL) & O_ACCMODE == O_RDONLY else { throw Fault54.alreadyUsed }
        var value = stat()
        guard fstat(selectedFD, &value) == 0, selectedIdentity.unchanged(value),
              value.st_mode & S_IFMT == S_IFREG, value.st_nlink == 1,
              value.st_mode & 0o022 == 0, value.st_size == expectedSize else { throw Fault54.unconfirmed }
        descriptor = fcntl(selectedFD, F_DUPFD_CLOEXEC, 0)
        guard descriptor >= 0 else { throw Fault54.unconfirmed }
        identity = selectedIdentity
        self.checkpoint = checkpoint
        try readBounded(copyTo: nil)
    }

    init(url: URL, size: Int64, sha256: String) throws {
        guard url.isFileURL && url.path.hasPrefix("/") && !url.path.utf8.contains(0),
              size > 0 && size <= 615_630_848,
              sha256.count == 64 && sha256.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { throw Fault54.invalidBinding }
        self.url = url; expectedSize = size; expectedSHA256 = sha256
    }
    func openAndPin() throws {
        guard descriptor == -1 && !closeAttempted else { throw Fault54.alreadyUsed }
        descriptor = url.path.withCString { Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
        guard descriptor >= 0 else { throw Fault54.unconfirmed }
        var value = stat()
        guard fstat(descriptor, &value) == 0, (value.st_mode & S_IFMT) == S_IFREG,
              (value.st_mode & 0o022) == 0, value.st_nlink == 1, value.st_size == expectedSize,
              value.st_uid == geteuid() || value.st_uid == 0 else { throw Fault54.unconfirmed }
        identity = FileIdentity54(value)
        try readBounded(copyTo: nil)
    }
    func verifyPathAndFD() throws {
        guard descriptor >= 0, let identity = identity else { throw Fault54.unconfirmed }
        var fd = stat(), path = stat()
        guard fstat(descriptor, &fd) == 0,
              url.path.withCString({ lstat($0, &path) }) == 0,
              identity.unchanged(fd), identity.unchanged(path) else { throw Fault54.unconfirmed }
    }
    func copyTo(_ output: Int32) throws { try readBounded(copyTo: output) }
    private func readBounded(copyTo output: Int32?) throws {
        try checkpoint()
        try verifyPathAndFD()
        var hasher = SHA256(), offset: Int64 = 0
        var bytes = [UInt8](repeating: 0, count: 65536)
        while offset < expectedSize {
            try checkpoint()
            let count = min(bytes.count, Int(expectedSize - offset))
            let got = bytes.withUnsafeMutableBytes { pread(descriptor, $0.baseAddress, count, off_t(offset)) }
            guard got > 0 && got <= count else { throw Fault54.unconfirmed }
            let data = Data(bytes[0..<got]); hasher.update(data: data)
            if let target = output {
                var written = 0
                while written < got {
                    let n = data.withUnsafeBytes { Darwin.write(target, $0.baseAddress!.advanced(by: written), got - written) }
                    guard n > 0 else { throw Fault54.unconfirmed }
                    written += n
                    try checkpoint()
                }
            }
            offset += Int64(got)
        }
        let actual = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        guard actual == expectedSHA256 else { throw Fault54.unconfirmed }
        try checkpoint()
        try verifyPathAndFD()
    }
    func closeOwned() -> Bool {
        guard !closeAttempted else { return false }
        closeAttempted = true
        if descriptor == -1 { return true }
        let saved = descriptor; descriptor = -1
        guard Darwin.close(saved) == 0 else { return false }
        errno = 0
        return fcntl(saved, F_GETFD) == -1 && errno == EBADF
    }
}
