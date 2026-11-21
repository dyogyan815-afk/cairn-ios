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
        let filesBridge = FilesBridge()
        let fetchBridge = FetchBridge()
        let userContent = WKUserContentController()
        userContent.add(bridge, name: SaveBridge.messageHandlerName)
        userContent.add(filesBridge, name: FilesBridge.messageHandlerName)
        userContent.add(fetchBridge, name: FetchBridge.messageHandlerName)
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

    // MARK: - Coordinator (navigation policy)

    // Note on downloads: the current WebKit SDK no longer exposes
    // WKWebView.downloadDelegate, so the WKDownloadDelegate fallback from the
    // original plan was removed (see docs/DECISIONS.md). Every real export path
    // goes through the save bridge; stray blob:/http(s) navigations are cancelled.
    final class Coordinator: NSObject, WKNavigationDelegate {
        weak var webView: WKWebView?
        var lastInboxVersion = -1

        func webView(_ webView: WKWebView,
                     decidePolicyFor navigationAction: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            let scheme = navigationAction.request.url?.scheme?.lowercased() ?? ""
            switch scheme {
            case SchemeHandler.scheme, "about":
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
    }
}
