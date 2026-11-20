import Foundation
import WebKit

/// Serves the bundled web app at cairn://app/... and the "Open in Cairn" file
/// at cairn://inbox/current (alias: cairn://app/inbox/current, so the page's
/// same-origin CSP applies to fetch()).
///
/// Pure helpers (mime/normalize/safe-path/Range parsing) are static and unit-tested.
final class SchemeHandler: NSObject, WKURLSchemeHandler {
    static let scheme = "cairn"
    static let appHost = "app"
    static let inboxHost = "inbox"
    static let inboxAliasPath = "/inbox/current"
    private static let streamChunkSize = 1 << 20 // 1 MiB

    private let inbox: InboxStore
    private let webRoot: URL?
    private let tasksLock = NSLock()
    private var liveTasks: [ObjectIdentifier: Any] = [:]

    init(inbox: InboxStore) {
        self.inbox = inbox
        self.webRoot = Bundle.main.url(forResource: "WebDist", withExtension: nil)
        super.init()
    }

    // MARK: - Pure helpers (unit tested)

    static func mime(for ext: String) -> String {
        switch ext.lowercased() {
        case "html", "htm": return "text/html"
        case "js", "mjs": return "text/javascript"
        case "css": return "text/css"
        case "svg": return "image/svg+xml"
        case "json", "map": return "application/json"
        case "png": return "image/png"
        case "jpg", "jpeg": return "image/jpeg"
        case "gif": return "image/gif"
        case "webp": return "image/webp"
        case "ico": return "image/x-icon"
        case "woff": return "font/woff"
        case "woff2": return "font/woff2"
        case "ttf": return "font/ttf"
        case "otf": return "font/otf"
        case "txt", "md": return "text/plain"
        case "pdf": return "application/pdf"
        case "wasm": return "application/wasm"
        case "webmanifest": return "application/manifest+json"
        default: return "application/octet-stream"
        }
    }

    /// Normalizes a request path: strips the leading slash, collapses duplicate
    /// slashes, maps "" to index.html. Percent-decoding is NOT applied here
    /// (WebKit gives us a decoded url.path already).
    static func normalizeAppPath(_ raw: String) -> String {
        var p = raw
        if p.hasPrefix("/") { p.removeFirst() }
        p = p.split(separator: "/", omittingEmptySubsequences: true).joined(separator: "/")
        if p.isEmpty { p = "index.html" }
        return p
    }

    /// Rejects anything that could escape the web root: "..", "." components,
    /// absolute paths, backslashes, or encoded traversal that survived decoding.
    static func isUnsafeAppPath(_ normalized: String) -> Bool {
        if normalized.contains("..") { return true }
        if normalized.contains("\\") { return true }
        if normalized.lowercased().contains("%2e") { return true }
        let comps = normalized.split(separator: "/").map(String.init)
        if comps.contains(".") { return true }
        if normalized.hasPrefix("/") { return true }
        return false
    }

    /// Parses an HTTP Range header for a file of the given size.
    /// Returns an inclusive (start, end) or nil for malformed/unsatisfiable input.
    /// Only the first range of a multi-range header is honoured.
    static func parseRange(_ header: String?, fileSize: Int64) -> (start: Int64, end: Int64)? {
        guard let h = header?.trimmingCharacters(in: .whitespaces),
              h.lowercased().hasPrefix("bytes=") else { return nil }
        let spec = String(h.dropFirst("bytes=".count)).trimmingCharacters(in: .whitespaces)
        guard !spec.isEmpty else { return nil }
        // Only the first range of a multi-range header is honoured.
        let first = spec.split(separator: ",", maxSplits: 1, omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .first ?? ""
        guard !first.isEmpty else { return nil }
        // open-ended: bytes=N-
        if first.hasSuffix("-") {
            let startStr = String(first.dropLast()).trimmingCharacters(in: .whitespaces)
            guard let s = Int64(startStr), s >= 0, s < fileSize else { return nil }
            return (s, fileSize - 1)
        }
        // suffix: bytes=-N (last N bytes)
        if first.hasPrefix("-") {
            let t = String(first.dropFirst()).trimmingCharacters(in: .whitespaces)
            guard let n = Int64(t), n > 0, fileSize > 0 else { return nil }
            return (max(0, fileSize - n), fileSize - 1)
        }
        // closed: bytes=A-B
        let kv = first.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: .whitespaces) }
        guard kv.count == 2, let s = Int64(kv[0]), let e = Int64(kv[1]) else { return nil }
        guard s >= 0, s <= e, s < fileSize else { return nil }
        return (s, min(e, fileSize - 1))
    }

    // MARK: - WKURLSchemeHandler

    func webView(_ webView: WKWebView, start task: WKURLSchemeTask) {
        track(task)
        guard let url = task.request.url, url.scheme?.lowercased() == SchemeHandler.scheme else {
            respondError(task, status: 400, message: "Unsupported request")
            return
        }
        let host = url.host?.lowercased() ?? ""
        let path = url.path
        if host == SchemeHandler.appHost {
            if path == SchemeHandler.inboxAliasPath { serveInbox(task, url: url); return }
            serveApp(task, url: url)
        } else if host == SchemeHandler.inboxHost, path == "/current" {
            serveInbox(task, url: url)
        } else {
            respondError(task, status: 404, message: "Not found")
        }
    }

    func webView(_ webView: WKWebView, stop task: WKURLSchemeTask) {
        untrack(task)
    }

    // MARK: - Serving

    private func serveApp(_ task: WKURLSchemeTask, url: URL) {
        guard let root = webRoot else {
            respondError(task, status: 500, message: "Web bundle missing")
            return
        }
        let normalized = SchemeHandler.normalizeAppPath(url.path)
        guard !SchemeHandler.isUnsafeAppPath(normalized) else {
            respondError(task, status: 400, message: "Unsafe path")
            return
        }
        let fileURL = root.appendingPathComponent(normalized)
        let rootPrefix = root.standardizedFileURL.path + "/"
        guard FileManager.default.fileExists(atPath: fileURL.path),
              fileURL.standardizedFileURL.path.hasPrefix(rootPrefix) else {
            respondError(task, status: 404, message: "Not found")
            return
        }
        let data = (try? Data(contentsOf: fileURL)) ?? Data()
        let headers = [
            "Content-Type": SchemeHandler.mime(for: fileURL.pathExtension),
            "Content-Length": String(data.count),
            "Cache-Control": "no-store",
        ]
        respond(task, url: url, status: 200, headers: headers, body: data)
    }

    private func serveInbox(_ task: WKURLSchemeTask, url: URL) {
        guard let fileURL = inbox.currentFileURL,
              FileManager.default.fileExists(atPath: fileURL.path) else {
            respondError(task, status: 404, message: "No inbox file")
            return
        }
        let attrs = try? FileManager.default.attributesOfItem(atPath: fileURL.path)
        let fileSize = (attrs?[.size] as? NSNumber)?.int64Value ?? 0

        if let r = SchemeHandler.parseRange(task.request.value(forHTTPHeaderField: "Range"), fileSize: fileSize) {
            let count = r.end - r.start + 1
            let headers = [
                "Content-Type": "application/octet-stream",
                "Content-Range": "bytes \(r.start)-\(r.end)/\(fileSize)",
                "Content-Length": String(count),
                "Accept-Ranges": "bytes",
            ]
            guard respond(task, url: url, status: 206, headers: headers, body: nil) else { return }
            stream(task: task, fileURL: fileURL, offset: r.start, count: count)
        } else {
            let headers = [
                "Content-Type": "application/octet-stream",
                "Content-Length": String(fileSize),
                "Accept-Ranges": "bytes",
            ]
            guard respond(task, url: url, status: 200, headers: headers, body: nil) else { return }
            stream(task: task, fileURL: fileURL, offset: 0, count: fileSize)
        }
    }

    private func stream(task: WKURLSchemeTask, fileURL: URL, offset: Int64, count: Int64) {
        guard let fh = try? FileHandle(forReadingFrom: fileURL) else {
            respondFail(task)
            return
        }
        defer { try? fh.close() }
        if offset > 0 { try? fh.seek(toOffset: UInt64(offset)) }
        var remaining = count
        while remaining > 0 {
            let want = min(Int64(SchemeHandler.streamChunkSize), remaining)
            guard let chunk = try? fh.read(upToCount: Int(want)), !chunk.isEmpty else { break }
            if !isLive(task) { return }
            task.didReceive(chunk)
            remaining -= Int64(chunk.count)
        }
        if isLive(task) { task.didFinish() }
    }

    // MARK: - Response plumbing

    @discardableResult
    private func respond(_ task: WKURLSchemeTask, url: URL, status: Int,
                         headers: [String: String], body: Data?) -> Bool {
        guard isLive(task) else { return false }
        let resp = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1",
                                   headerFields: headers)
            ?? HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil)!
        task.didReceive(resp)
        if let body { task.didReceive(body) }
        if !body.isNil { task.didFinish() }
        return true
    }

    private func respondError(_ task: WKURLSchemeTask, status: Int, message: String) {
        guard let url = task.request.url else {
            if isLive(task) { task.didFailWithError(URLError(.badURL)) }
            return
        }
        let body = Data(message.utf8)
        _ = respond(task, url: url, status: status,
                    headers: ["Content-Type": "text/plain", "Content-Length": String(body.count)],
                    body: body)
    }

    private func respondFail(_ task: WKURLSchemeTask) {
        if isLive(task) { task.didFailWithError(NSError(domain: NSCocoaErrorDomain,
                                              code: NSFileReadUnknownError,
                                              userInfo: [NSLocalizedDescriptionKey: "Cannot read inbox file"])) }
    }

    // MARK: - Live-task tracking (avoids crashing if WebKit cancels mid-stream)

    private func track(_ task: WKURLSchemeTask) {
        tasksLock.lock()
        liveTasks[ObjectIdentifier(task)] = task
        tasksLock.unlock()
    }

    private func untrack(_ task: WKURLSchemeTask) {
        tasksLock.lock()
        liveTasks.removeValue(forKey: ObjectIdentifier(task))
        tasksLock.unlock()
    }

    private func isLive(_ task: WKURLSchemeTask) -> Bool {
        tasksLock.lock()
        defer { tasksLock.unlock() }
        return liveTasks[ObjectIdentifier(task)] != nil
    }
}

private extension Optional where Wrapped == Data {
    var isNil: Bool {
        switch self {
        case .none: return true
        case .some: return false
        }
    }
}
