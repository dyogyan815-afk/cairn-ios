import Foundation

/// Holds the file received via "Open in Cairn".
/// Thread-safe: the scheme handler reads from a background thread,
/// while `receive(_:)` is called from the UI thread.
final class InboxStore: NSObject {
    /// Called on the main thread whenever a new inbox file is available.
    var onChange: (() -> Void)?

    private let lock = NSLock()
    private var _currentFileURL: URL?
    private let inboxDir: URL

    override init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        inboxDir = support.appendingPathComponent("Inbox", isDirectory: true)
        super.init()
        try? FileManager.default.createDirectory(at: inboxDir, withIntermediateDirectories: true)
    }

    /// Currently stored inbox file, if any.
    var currentFileURL: URL? {
        lock.lock()
        defer { lock.unlock() }
        return _currentFileURL
    }

    /// Copies a security-scoped file handed over by the system into the private
    /// inbox directory. Copying (instead of serving in place) keeps lifetime
    /// management of security scopes simple and deterministic.
    func receive(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let ext = url.pathExtension.isEmpty ? "ipa" : url.pathExtension
        let dest = inboxDir.appendingPathComponent("current.\(ext.lowercased())")
        do {
            if FileManager.default.fileExists(atPath: dest.path) {
                try FileManager.default.removeItem(at: dest)
            }
            try FileManager.default.copyItem(at: url, to: dest)
            lock.lock()
            _currentFileURL = dest
            lock.unlock()
            DispatchQueue.main.async { [weak self] in self?.onChange?() }
        } catch {
            lock.lock()
            _currentFileURL = nil
            lock.unlock()
        }
    }

    func clear() {
        lock.lock()
        let old = _currentFileURL
        _currentFileURL = nil
        lock.unlock()
        if let old { try? FileManager.default.removeItem(at: old) }
    }
}
