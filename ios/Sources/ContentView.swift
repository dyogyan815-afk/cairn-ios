import SwiftUI
import WebKit

/// Observable shell so SwiftUI can trigger a page reload when a new inbox file
/// arrives ("Open in Cairn").
@MainActor
final class Shell: ObservableObject {
    let inbox = InboxStore()
    @Published var inboxVersion = 0

    init() {
        inbox.onChange = { [weak self] in
            self?.inboxVersion += 1
        }
    }
}

struct ContentView: View {
    @ObservedObject var shell: Shell

    var body: some View {
        WebView(shell: shell)
            .ignoresSafeArea()
    }
}

struct WebView: UIViewRepresentable {
    @ObservedObject var shell: Shell

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.setURLSchemeHandler(SchemeHandler(inbox: shell.inbox), forURLScheme: SchemeHandler.scheme)

        let bridge = SaveBridge()
        let userContent = WKUserContentController()
        userContent.add(bridge, name: SaveBridge.messageHandlerName)
        userContent.addUserScript(
            WKUserScript(source: SaveBridge.userScriptSource,
                         injectionTime: .atDocumentEnd,
                         forMainFrameOnly: false))
        config.userContentController = userContent

        let webView = WKWebView(frame: .zero, configuration: config)
        webView.isOpaque = false
        webView.backgroundColor = .systemBackground
        webView.scrollView.contentInsetAdjustmentBehavior = .never
        webView.allowsBackForwardNavigationGestures = false
        webView.navigationDelegate = context.coordinator
        webView.downloadDelegate = context.coordinator
        bridge.attach(webView)
        context.coordinator.webView = webView

        if let start = URL(string: "cairn://app/index.html") {
            webView.load(URLRequest(url: start))
        }
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        // Reload once when a new inbox file arrives so the page picks it up.
        if context.coordinator.lastInboxVersion != shell.inboxVersion {
            context.coordinator.lastInboxVersion = shell.inboxVersion
            if shell.inboxVersion > 0, let start = URL(string: "cairn://app/index.html") {
                webView.load(URLRequest(url: start))
            }
        }
    }

    // MARK: - Coordinator (navigation policy + WKDownloadDelegate fallback)

    final class Coordinator: NSObject, WKNavigationDelegate, WKDownloadDelegate {
        weak var webView: WKWebView?
        var lastInboxVersion = -1
        private var downloads: [ObjectIdentifier: (download: WKDownload, destination: URL?)] = [:]

        // Only our own scheme, blob: previews/downloads and about: are allowed.
        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            let scheme = navigationAction.request.url?.scheme?.lowercased() ?? ""
            switch scheme {
            case SchemeHandler.scheme, "blob", "about":
                decisionHandler(.allow)
            default:
                decisionHandler(.cancel)
            }
        }

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationResponse: WKNavigationResponse,
                     decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
            decisionHandler(.allow)
        }

        // blob: anchor downloads become WKDownload objects; route them to the
        // share sheet as a fallback for anything that skipped the save bridge.
        func webView(_ webView: WKWebView,
                     navigationResponse: WKNavigationResponse,
                     didBecome download: WKDownload) {
            track(download)
        }

        func webView(_ webView: WKWebView,
                     navigationAction: WKNavigationAction,
                     didBecome download: WKDownload) {
            track(download)
        }

        func download(_ download: WKDownload,
                      decideDestinationUsing response: URLResponse,
                      completionHandler: @escaping (URL?) -> Void) {
            let dir = FileManager.default.temporaryDirectory
                .appendingPathComponent("cairn-exports", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let suggested = response.suggestedFilename ?? "download.bin"
            let safe = suggested.replacingOccurrences(of: "/", with: "_")
            let url = dir.appendingPathComponent("\(UUID().uuidString)-\(safe)")
            FileManager.default.createFile(atPath: url.path, contents: nil)
            downloads[ObjectIdentifier(download)] = (download, url)
            completionHandler(url)
        }

        func download(_ download: WKDownload,
                      didReceive authenticationChallenge: URLAuthenticationChallenge,
                      completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            completionHandler(.performDefaultHandling, nil)
        }

        func downloadDidFinish(_ download: WKDownload) {
            let key = ObjectIdentifier(download)
            guard let entry = downloads.removeValue(forKey: key), let url = entry.destination else { return }
            if let wv = webView {
                DispatchQueue.main.async { UIActivityPresenter.present(url: url, from: wv) }
            }
        }

        func download(_ download: WKDownload,
                      didFailWithError error: Error,
                      resumeData: Data?) {
            let key = ObjectIdentifier(download)
            if let entry = downloads.removeValue(forKey: key), let url = entry.destination {
                try? FileManager.default.removeItem(at: url)
            }
        }

        private func track(_ download: WKDownload) {
            downloads[ObjectIdentifier(download)] = (download, nil)
        }
    }
}
