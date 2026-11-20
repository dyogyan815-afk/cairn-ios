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
            self.tmpDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("cairn-exports", isDirectory: true)
        }
    }

    func begin() throws {
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        let sanitized = name
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: ":", with: "_")
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
    static func present(url: URL, from webView: WKWebView) {
        guard var top = webView.window?.rootViewController else { return }
        while let p = top.presentedViewController { top = p }
        let av = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        av.completionWithItemsHandler = { _, _, _, _ in
            try? FileManager.default.removeItem(at: url)
        }
        if UIDevice.current.userInterfaceIdiom == .pad {
            av.popoverPresentationController?.sourceView = webView
            av.popoverPresentationController?.sourceRect = CGRect(
                x: webView.bounds.midX, y: webView.bounds.midY, width: 1, height: 1)
        }
        top.present(av, animated: true)
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
