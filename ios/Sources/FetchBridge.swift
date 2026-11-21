import Foundation
import WebKit

/// WKScriptMessageHandler for the "cairnFetch" channel: performs HTTP GETs
/// NATIVELY for the page's "Images from a link" feature.
///
/// Why native: the page ships a strict Content-Security-Policy
/// (connect-src 'self') so the web app itself can never talk to the network.
/// The fetch therefore runs in the app process, only after the user taps
/// "Fetch all images", only for http(s) URLs, with a hard byte cap so a
/// huge response can never exhaust memory (the transfer is cancelled the
/// moment the cap is exceeded — nothing is buffered beyond it).
final class FetchBridge: NSObject, WKScriptMessageHandler {
    static let messageHandlerName = "cairnFetch"
    static let defaultMaxBytes = 8 << 20

    typealias Loader = (URLRequest, Int, @escaping (Result<(Data, HTTPURLResponse?), Error>) -> Void) -> Void
    private weak var webView: WKWebView?
    private let loader: Loader
    /// Test seam: when set, response JS is delivered here instead of WKWebView.
    var responderOverride: ((String) -> Void)?

    init(webView: WKWebView? = nil, loader: Loader? = nil) {
        self.webView = webView
        self.loader = loader ?? { request, maxBytes, completion in
            let session = CappedDownload.start(urlRequest: request, cap: maxBytes, onDone: completion)
            _ = session // retained by its own delegate until invalidated
        }
        super.init()
    }

    func attach(_ webView: WKWebView) { self.webView = webView }

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        guard message.name == FetchBridge.messageHandlerName else { return }
        guard let body = message.body as? [String: Any] else { return }
        handle(body)
    }

    /// JS-visible behaviour, separated from WKScriptMessage for unit tests.
    /// Response to the page: window event 'cairnfetch' with detail
    /// {req, ok, status?, finalUrl?, data? (base64), error?}.
    func handle(_ body: [String: Any]) {
        let req = (body["req"] as? NSNumber)?.intValue ?? 0
        let maxBytes = (body["maxBytes"] as? NSNumber)?.intValue ?? FetchBridge.defaultMaxBytes

        func respond(_ payload: [String: Any]) {
            var full: [String: Any] = ["req": req]
            payload.forEach { full[$0.key] = $0.value }
            guard let data = try? JSONSerialization.data(withJSONObject: full, options: [.fragmentsAllowed]),
                  let json = String(data: data, encoding: .utf8) else { return }
            let js = "window.dispatchEvent(new CustomEvent('cairnfetch',{detail:\(json)}))"
            DispatchQueue.main.async { [weak self] in
                if let responder = self?.responderOverride { responder(js); return }
                self?.webView?.evaluateJavaScript(js, completionHandler: nil)
            }
        }

        guard let raw = body["url"] as? String, let url = URL(string: raw), let scheme = url.scheme?.lowercased() else {
            respond(["ok": false, "error": "not a valid URL"])
            return
        }
        // Only real web origins. file:, cairn:, app schemes are refused so the
        // bridge can never be used to read app-internal resources.
        guard scheme == "http" || scheme == "https" else {
            respond(["ok": false, "error": "only http(s) links can be fetched"])
            return
        }
        var request = URLRequest(url: url, timeoutInterval: 30)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        loader(request, maxBytes) { result in
            switch result {
            case .failure(let e):
                respond(["ok": false, "error": e.localizedDescription])
            case .success(let (data, response)):
                let status = response?.statusCode ?? 0
                if let http = response, !(200...299).contains(http.statusCode) {
                    respond(["ok": false, "status": status,
                             "error": "HTTP \(http.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: http.statusCode))"])
                    return
                }
                guard !data.isEmpty else {
                    respond(["ok": false, "status": status, "error": "empty response"])
                    return
                }
                respond(["ok": true, "status": status,
                         "finalUrl": response?.url?.absoluteString ?? url.absoluteString,
                         "data": data.base64EncodedString()])
            }
        }
    }
}

/// URLSessionDataDelegate that cancels the transfer as soon as the byte cap
/// is exceeded — the app never holds more than `cap` (+ one chunk) in memory.
final class CappedDownload: NSObject, URLSessionDataDelegate {
    private let cap: Int
    private let onDone: (Result<(Data, HTTPURLResponse?), Error>) -> Void
    private var data = Data()
    private var response: HTTPURLResponse?
    private var finished = false
    private var session: URLSession!

    static func start(urlRequest: URLRequest, cap: Int, onDone: @escaping (Result<(Data, HTTPURLResponse?), Error>) -> Void) -> URLSession {
        let d = CappedDownload(cap: cap, onDone: onDone)
        let s = URLSession(configuration: .ephemeral, delegate: d, delegateQueue: nil)
        d.session = s
        s.dataTask(with: urlRequest).resume()
        return s
    }

    private init(cap: Int, onDone: @escaping (Result<(Data, HTTPURLResponse?), Error>) -> Void) {
        self.cap = cap
        self.onDone = onDone
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask,
                    didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        self.response = response as? HTTPURLResponse
        if let expected = response.expectedContentLength, expected > Int64(cap) {
            finish(.failure(CappedDownload.FetchError(message: "response is larger than the \(cap / (1 << 20)) MB limit")))
            completionHandler(.cancel)
            return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard !finished else { return }
        self.data.append(data)
        if self.data.count > cap {
            finish(.failure(CappedDownload.FetchError(message: "response is larger than the \(cap / (1 << 20)) MB limit")))
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard !finished else { return }
        if let e = error as NSError?, e.code == NSURLErrorCancelled {
            return // already finished via the byte cap; no duplicate completion
        }
        if let e = error {
            finish(.failure(e))
            return
        }
        finish(.success((data, response)))
    }

    private func finish(_ result: Result<(Data, HTTPURLResponse?), Error>) {
        guard !finished else { return }
        finished = true
        session.finishTasksAndInvalidate()
        onDone(result)
    }

    struct FetchError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }
}
