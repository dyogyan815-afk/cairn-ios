import Foundation
import UIKit
import WebKit

/// Receives streamed export data from the page (window.__cairnNativeSaver in
/// BridgeJS) in 1-4 MB base64 chunks: begin → chunk* → finish | abort.
final class ExportSession {
    let name: String
    let expectedSize: Int64
    private(set) var fileURL: URL?
    private(set) var received: Int64 = 0
    private var handle: FileHandle?
    private let tmpDir: URL

    struct ExportError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    init(name: String, expectedSize: Int64, tmpDir: URL? = nil) {
        self.name = name
        self.expectedSize = expectedSize
        if let tmpDir {
            self.tmpDir = tmpDir
        } else {
            // Persistent, Files-app-visible location (UIFileSharingEnabled = true):
            // Files app → On My iPhone → Cairn → Exports. Exports are kept, not
            // deleted after the share sheet is dismissed, so nothing is ever lost.
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            self.tmpDir = docs.appendingPathComponent("Exports", isDirectory: true)
        }
    }

    func begin() throws {
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        let sanitized = name
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
            .replacingOccurrences(of: "..", with: "__")
            .replacingOccurrences(of: "\0", with: "_")
        let url = tmpDir.appendingPathComponent("\(UUID().uuidString)-\(sanitized)")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try FileHandle(forWritingTo: url)
        fileURL = url
        received = 0
    }

    func append(base64: String) throws {
        guard let d = Data(base64Encoded: base64, options: [.ignoreUnknownCharacters]) else {
            throw ExportError(message: "Bad base64 chunk")
        }
        try append(data: d)
    }

    func append(data: Data) throws {
        guard let h = handle else { throw ExportError(message: "Chunk before begin") }
        try h.write(contentsOf: data)
        received += Int64(data.count)
    }

    /// Closes the file and returns its URL. If the caller announced a size and
    /// the bytes do not match, the temp file is deleted and an error thrown.
    func finish() throws -> URL {
        try? handle?.close()
        handle = nil
        guard let url = fileURL else { throw ExportError(message: "Finish before begin") }
        if expectedSize > 0, received != expectedSize {
            try? FileManager.default.removeItem(at: url)
            fileURL = nil
            throw ExportError(message: "Size mismatch: got \(received) of \(expectedSize) bytes")
        }
        return url
    }

    func abort() {
        try? handle?.close()
        handle = nil
        if let url = fileURL {
            try? FileManager.default.removeItem(at: url)
            fileURL = nil
        }
    }
}

/// WKScriptMessageHandler for the "cairnSave" message channel.
final class SaveBridge: NSObject, WKScriptMessageHandler {
    static let messageHandlerName = "cairnSave"
    static let userScriptSource: String = BridgeJS.source

    private let lock = NSLock()
    private var sessions: [String: ExportSession] = [:]
    private weak var webView: WKWebView?

    init(webView: WKWebView? = nil) {
        self.webView = webView
        super.init()
    }

    func attach(_ webView: WKWebView) {
        self.webView = webView
    }

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard message.name == SaveBridge.messageHandlerName else { return }
        guard let body = message.body as? [String: Any] else { return }
        let kind = body["kind"] as? String ?? ""
        let name = (body["name"] as? String) ?? "export.zip"
        lock.lock()
        defer { lock.unlock() }
        switch kind {
        case "begin":
            let size = (body["size"] as? NSNumber)?.int64Value ?? 0
            let session = ExportSession(name: name, expectedSize: size)
            do {
                try session.begin()
                sessions[name] = session
            } catch {
                reportFailure(name, error)
            }
        case "chunk":
            guard let session = sessions[name] else {
                reportFailure(name, ExportSession.ExportError(message: "No active session for \(name)"))
                break
            }
            if let chunk = body["data"] as? String {
                do {
                    try session.append(base64: chunk)
                } catch {
                    sessions.removeValue(forKey: name)
                    session.abort()
                    reportFailure(name, error)
                }
            }
        case "finish":
            guard let session = sessions.removeValue(forKey: name) else { break }
            do {
                let url = try session.finish()
                reportSuccess(name: name, url: url)
                presentShare(url: url)
            } catch {
                session.abort()
                reportFailure(name, error)
            }
        case "abort":
            if let session = sessions.removeValue(forKey: name) {
                session.abort()
            }
        default:
            break
        }
    }

    func sessionCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return sessions.count
    }

    // MARK: - Share sheet

    private func presentShare(url: URL) {
        guard let wv = webView else { return }
        DispatchQueue.main.async {
            UIActivityPresenter.present(url: url, from: wv)
        }
    }

    private func reportSuccess(name: String, url: URL) {
        let rel = "Exports/\(url.lastPathComponent)"
        let js = "window.dispatchEvent(new CustomEvent('cairnsaveok',{detail:{name:\(JS.quote(name)),file:\(JS.quote(rel))}}))"
        DispatchQueue.main.async { [weak self] in
            self?.webView?.evaluateJavaScript(js, completionHandler: nil)
        }
    }

    private func reportFailure(_ name: String, _ error: Error) {
        let msg = error.localizedDescription
        let js = "window.dispatchEvent(new CustomEvent('cairnsavefail',{detail:{name:\(JS.quote(name)),message:\(JS.quote(msg))}}))"
        DispatchQueue.main.async { [weak self] in
            self?.webView?.evaluateJavaScript(js, completionHandler: nil)
        }
    }
}

/// Shared presentation of the "Save to Files" sheet.
enum UIActivityPresenter {
    static func present(url: URL, from webView: WKWebView?) {
        guard let wv = webView, var top = wv.window?.rootViewController else { return }
        while let p = top.presentedViewController { top = p }
        let av = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        // The file is NOT removed on completion: it stays in Documents/Exports so
        // the user can share it again later from the "Phone files" card.
        if UIDevice.current.userInterfaceIdiom == .pad {
            av.popoverPresentationController?.sourceView = wv
            av.popoverPresentationController?.sourceRect = CGRect(
                x: wv.bounds.midX, y: wv.bounds.midY, width: 1, height: 1)
        }
        top.present(av, animated: true)
    }
}

/// WKScriptMessageHandler for the "cairnFiles" channel: lets the page list,
/// re-share and remove the files saved in Documents/Exports at any time.
final class FilesBridge: NSObject, WKScriptMessageHandler {
    static let messageHandlerName = "cairnFiles"

    static var exportsDir: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("Exports", isDirectory: true)
    }

    static func sanitize(_ name: String) -> String? {
        let clean = name
            .replacingOccurrences(of: "\u{0}", with: "_")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "..", with: "__")
        return clean.isEmpty || clean.contains("..") ? nil : clean
    }

    static func listExports(in dir: URL) -> [[String: Any]] {
        let fm = FileManager.default
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let keys: [URLResourceKey] = [.fileSizeKey, .contentModificationDateKey]
        guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: keys) else { return [] }
        return items
            .filter { !$0.hasDirectoryPath }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { url in
                let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
                let mod = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate?.timeIntervalSince1970 ?? 0
                return ["name": url.lastPathComponent, "size": size, "modified": mod]
            }
    }

    private weak var webView: WKWebView?

    init(webView: WKWebView? = nil) {
        self.webView = webView
        super.init()
    }

    func attach(_ webView: WKWebView) { self.webView = webView }

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard message.name == FilesBridge.messageHandlerName else { return }
        guard let body = message.body as? [String: Any] else { return }
        let kind = body["kind"] as? String ?? ""
        let req = (body["req"] as? NSNumber)?.intValue ?? 0
        switch kind {
        case "list":
            respond(req: req, extra: ["files": FilesBridge.listExports(in: FilesBridge.exportsDir)])
        case "share":
            guard let raw = body["name"] as? String, let safe = FilesBridge.sanitize(raw) else { return }
            let url = FilesBridge.exportsDir.appendingPathComponent(safe)
            if FileManager.default.fileExists(atPath: url.path) {
                DispatchQueue.main.async { [weak self] in
                    UIActivityPresenter.present(url: url, from: self?.webView)
                }
            } else {
                respond(req: req, extra: ["error": "File not found: \(safe)"])
            }
        case "delete":
            guard let raw = body["name"] as? String, let safe = FilesBridge.sanitize(raw) else { return }
            try? FileManager.default.removeItem(at: FilesBridge.exportsDir.appendingPathComponent(safe))
            respond(req: req, extra: ["files": FilesBridge.listExports(in: FilesBridge.exportsDir)])
        default:
            break
        }
    }

    private func respond(req: Int, extra: [String: Any]) {
        var payload: [String: Any] = ["req": req]
        extra.forEach { payload[$0.key] = $0.value }
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.fragmentsAllowed]),
              let json = String(data: data, encoding: .utf8) else { return }
        let js = "window.dispatchEvent(new CustomEvent('cairnfiles',{detail:\(json)}))"
        DispatchQueue.main.async { [weak self] in
            self?.webView?.evaluateJavaScript(js, completionHandler: nil)
        }
    }
}

enum JS {
    static func quote(_ s: String) -> String {
        let escaped = s
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
        return "\"\(escaped)\""
    }
}
