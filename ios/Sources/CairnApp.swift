import SwiftUI

@main
struct CairnApp: App {
    @StateObject private var shell = Shell()

    var body: some Scene {
        WindowGroup {
            ContentView(shell: shell)
                // "Open in Cairn": Files app / other apps hand over an .ipa or .zip here.
                .onOpenURL { url in shell.inbox.receive(url) }
        }
    }
}
