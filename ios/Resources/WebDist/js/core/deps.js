// Dependency engine (otool -L across every Mach-O in the app, linked into one
// report): for each binary it lists the linked libraries and then classifies
// each link as system, embedded (ships inside the IPA) or MISSING (neither
// system-wide nor embedded — the app would crash to launch or to load it).
const SYSTEM_PREFIX = /^\/?(System|usr\/lib|Applications\/Xcode|Library\/Developer)/;
const SYSTEM_LIBS = new Set([
  'UIKit', 'Foundation', 'CoreFoundation', 'CoreGraphics', 'CoreAnimation', 'QuartzCore',
  'CoreData', 'CoreText', 'CoreImage', 'CoreVideo', 'CoreMedia', 'CoreTelephony', 'CoreLocation',
  'CoreAudio', 'CoreBluetooth', 'CoreMotion', 'CoreSpotlight', 'CoreServices', 'CoreData',
  'CloudKit', 'CFNetwork', 'Security', 'WebKit', 'SafariServices', 'StoreKit', 'UserNotifications',
  'UserUI', 'MapKit', 'MessageUI', 'EventKit', 'HealthKit', 'HomeKit', 'LocalAuthentication',
  'Photos', 'PhotosUI', 'Contacts', 'ContactsUI', 'MediaPlayer', 'AVFoundation', 'AudioToolbox',
  'AudioUnit', 'Metal', 'MetalKit', 'MetalPerformanceShaders', 'SceneKit', 'SpriteKit', 'GLKit',
  'GameKit', 'GameplayKit', 'ReplayKit', 'MultipeerConnectivity', 'ExternalAccessory', 'NotificationCenter',
  'ActivityKit', 'AppTrackingTransparency', 'ARKit', 'AVKit', 'AdSupport', 'AssetsLibrary',
  'BackgroundTasks', 'BusinessChat', 'CallKit', 'CarPlay', 'ClassKit', 'Combine', 'Cryph', 'CryptoKit',
  'DeviceCheck', 'FileProvider', 'FileProviderUI', 'Fitness', 'GSS', 'IOSurface', 'IdentityLookup',
  'IdentityLookupUI', 'Intents', 'IntentsUI', 'JSContext', 'LinkPresentation', 'LiveCommunicationKit',
  'MachineLearning', 'ManagedConfiguration', 'Maps', 'MediaAccessibility', 'MediaLibrary', 'MediaPlayerUI',
  'Messages', 'MetalFX', 'MetricKit', 'MLCompute', 'MobileCoreServices', 'MultitaskingCameraAccess',
  'NaturalLanguage', 'NearFieldInteraction', 'Network', 'NewsUI', 'ObjectiveC', 'OpenGLES', 'OSLog',
  'PassKit', 'PDFKit', 'PushKit', 'QuickLook', 'QuickLookThumbnailing', 'RemoteInput', 'ResponseKit',
  'SafariCore', 'Sensory', 'SensorKit', 'SignpostCollection', 'SignpostSupport', 'Social', 'SoundAnalysis',
  'Speech', 'SpriteKit', 'SwiftUI', 'SwiftUICore', 'Symptoms', 'SystemConfiguration', 'ThreadNetwork',
  'Triangulate', 'Tweet extension', 'Twitter', 'UIKitCore', 'UniformTypeIdentifiers', 'VideoSubscriberAccount',
  'VideoToolbox', 'Virtualization', 'Vision', 'VisionKit', 'WatchConnectivity', 'WatchKit', 'WeatherKit',
  'WebInspector', 'WebUI', 'WifiManager', 'WidgetKit', 'WirelessInsights', 'Accessibility', 'Accelerate',
  'Accounts', 'AddressBook', 'AppClip', 'AppleFileSystemServices', 'ApplicationServices', 'ArchiveService',
  'AssertionServices', 'AudioStreaming', 'BaseBoardUI', 'BaseBoard', 'BiometricKit', 'BLEClientSupport',
  'BluetoothManager', 'BoardServices', 'Bom', 'BoringSSL', 'BoringSSL_GRPOpenSSL', 'ByteRangeController',
  'C2', 'CalendarFoundation', 'CanvasKit', 'CaptiveNetworkSupport', 'ChunkedCDN', 'Ciphers', 'ClockKit',
  'ColorSync', 'CommonCrypto', 'ConfigurationEngine', 'ContactsFoundation', 'ContentIndex',
  'Convergence', 'CredentialManagement', 'CryptoTokenKit', 'DAPaths', 'DataDetectorsCore', 'DataDeliveryServices',
  'DateTools', 'DesktopServices', 'DeviceLink', 'DiskArbitration', 'Distill', 'DuetActivityScheduler',
  'DuetExpertConfig', 'Dyld', 'DyldOSMConstants', 'DynamiteCore', 'ESRTabbedPanel', 'EXORpcSecurity',
  'ExtensionKit', 'ExtensionFoundation', 'FCEventStream', 'FWA', 'FamilyControls', 'FamilyCircle',
  'FastRLIOSurface', 'FileManagement', 'FindMyDevice', 'FirmwareServices', 'FrontBoardServices',
  'FrontBoard', 'FTClientServices', 'GeoServices', 'IOKit', 'ImageCaptureCore', 'ImageIO',
  'IntentsFoundation', 'IOAccelerator', 'IOGPU', 'IOMobileFramebuffer', 'IOVideo', 'JournalingSupport',
  'KeyData', 'LanguageModeling', 'Lexicon', 'libarchive', 'libCRFSuite', 'libc.dylib', 'libcompression',
  'libcrypto.dylib', 'libcups', 'libcvaplink', 'libdebugnetworkextension', 'libcache.dylib', 'libclang_rt.asan_ios_dynamic.dylib',
  'libgraphic_tracker', 'libIOReport', 'libicucore', 'libLockdownCustomEngine', 'liblangid', 'libmalloc',
  'libMobileGestalt', 'libnetwork.dylib', 'libobjc.dylib', 'libPhaseUtils', 'libsqlite3.dylib', 'libssl.dylib',
  'libSystem.dylib', 'libsystem_kernel.dylib', 'libsyscall', 'libTelephonyUtil', 'libTitan', 'libAccessibility',
  'libCoreVMClient', 'libCRFSuite', 'libexfat', 'libstdc++.dylib', 'libz.dylib', 'libxml2.dylib', 'libxslt.dylib',
  'MachineSettings', 'ManagedAppConfiguration', 'ManagedAppUI', 'ManagedSettings', 'MediaAnalysis',
  'MediaServices', 'MetabolicKit', 'Micro-location', 'MobileAsset', 'MobileBackup', 'MobileDevice',
  'MobileKeyBag', 'MobileSafari', 'MobileStorage', 'MobileTimer', 'Navigation', 'Netrb', 'Notes',
  'OnDemandResources', 'OpenCL', 'OpenGL', 'OSAKit', 'OSSupport', 'PAR', 'Pegasus', 'PersonaUI',
  'PhotoFoundation', 'PhotoIngest', 'PhotosUtility', 'PipelineKit', 'PlugInKit', 'Preferences',
  'PrintKit', 'ProtocolBuffer', 'Proximity', 'Provisioning', 'ProxySupport', 'QuartzFilters', 'QuickLookSupport',
  'Radio', 'RemoteUI', 'RecordingIndicator', 'RunningBoard', 'SafariShared', 'ScreencastUIService', 'ScreenTime',
  'SearchFoundation', 'SharedUtils', 'Sharing', 'SharingUI', 'SignpostNotification', 'SiriUICore', 'SoftLinking',
  'Spotlight', 'SpotlightUI', 'SpringBoard', 'StorageKit', 'StreamingSupport', 'SymptomDiagnosticReporter',
  'SyncedScreenSaver', 'System', 'SystemIdentifiers', 'TelephonyUI', 'TextExtrusion', 'TextRecognition',
  'TextSpeech', 'TextureIO', 'ThermalMonitor', 'TimeSync', 'Tungsten', 'UIKitServices', 'UIFoundation',
  'UniversalAccess', 'ViceroyTrace', 'VideoProcessing', 'vImage', 'WeatherFoundation', 'WebBookmarks',
  'WebCore', 'WebFoundation', 'WebKitLegacy', 'WirelessDiagnostics', 'WorkoutForecast', 'XCUIAutomation',
]);

const basename = (p) => p.replace(/^.*\//, '');

export function isSystemLib(pathOrName) {
  if (SYSTEM_PREFIX.test(pathOrName)) return true;
  const b = basename(pathOrName);
  if (SYSTEM_LIBS.has(b)) return true;
  // system dylibs ship as libX.dylib or X.framework/X under /System
  if (/^(libobjc|libsystem|libSystem|libdispatch|libicucore|libsqlite3|libz\.|libxml2|libxslt|libswiftCore|libswift[A-Z]|libc\+\+|libc\.|libcompression|libresolv|libutil|libMobileGestalt|libnetwork|libarchive|libCRFSuite|libc\.dylib)/.test(b)) return true;
  return false;
}

export function embeddedBasenames(model) {
  // every Mach-O-ish file that actually ships inside this IPA (by basename)
  const set = new Set();
  for (const f of model.files) {
    if (f.isDir) continue;
    if (/\.(dylib|dylib2)$/i.test(f.ext === '' ? f.path : '') || f.path.endsWith('.dylib')) set.add(basename(f.path));
    if (/\/Frameworks\/.*\.framework\/(Versions\/[A-Z]\/)?[A-Z]/.test(f.path) && !f.path.endsWith('/')) set.add(basename(f.path));
    if (f.path.endsWith('.app/') === false && /Payload\/[^/]+\.app\/[^/]+$/.test(f.path) && !f.path.includes('.bundle/') && !f.path.includes('.lproj/') && !/\.(png|car|plist|strings|nib|momd|mom|dat|json|html|css|js|txt|jpg|jpeg|pdf|ttf|otf|mp3|mp4|wav|caf|lproj|storyboardc|xib|aab|lic|bin)$/i.test(f.path)) {
      // main executable + plugin executables: files directly inside .app or .appex roots
      if (/Payload\/[^/]+(\.app|\.appex)\/[^/]+$/.test(f.path)) set.add(basename(f.path));
    }
  }
  return set;
}

/** Build the dependency report for every Mach-O found in the model.
 * getBytes(path) must return Uint8Array for a file (bounded). */
export async function buildDeps(model, getBytes, { maxBytes = 96 << 20 } = {}) {
  const targets = model.files.filter((f) => !f.isDir && (f.path.endsWith('.dylib') || /\/(Frameworks|PlugIns|Watch|Extensions)\//.test(f.path) && !f.path.endsWith('/') || /Payload\/[^/]+\.(app|appex)\/[^/]+$/.test(f.path) && !/\.(png|car|plist|strings|nib|momd|mom|dat|json|html|css|js|txt|jpg|jpeg|pdf|ttf|otf|mp3|mp4|wav|caf|lproj|storyboardc|xib)$/i.test(f.path)));
  const embedded = embeddedBasenames(model);
  const binaries = [];
  const seen = new Set();
  for (const t of targets) {
    if (seen.has(t.path)) continue;
    seen.add(t.path);
    if (t.size > maxBytes) continue;
    let macho;
    try {
      const { parseMachO } = await import('./macho.js');
      const bytes = (await getBytes(t, 8 << 20)).bytes; // header + load commands live at the start
      if (!bytes || !bytes.length) continue;
      macho = parseMachO(bytes);
      if (!macho.ok) continue;
    } catch { continue; }
    const links = [];
    for (const sl of macho.slices) {
      if (!sl.ok) continue;
      for (const d of sl.dylibs || []) {
        const base = basename(d.name);
        const kind = isSystemLib(d.name) ? 'system' : embedded.has(base) ? 'embedded' : 'missing';
        links.push({ name: d.name, base, kind, current: d.current, compat: d.compat, from: t.path, arch: sl.arch });
      }
      for (const d of sl.weakDylibs || []) {
        const base = basename(d.name);
        const kind = isSystemLib(d.name) ? 'system (weak)' : embedded.has(base) ? 'embedded (weak)' : 'missing (weak)';
        links.push({ name: d.name, base, kind, current: d.current, compat: d.compat, from: t.path, arch: sl.arch, weak: true });
      }
    }
    if ((macho.slices[0] && macho.slices[0].ok)) {
      binaries.push({ path: t.path, size: t.size, archs: macho.slices.filter((s) => s.ok).map((s) => s.arch), links });
    }
  }
  const all = binaries.flatMap((b) => b.links);
  const tally = { system: 0, embedded: 0, missing: 0 };
  const unique = new Map();
  for (const l of all) {
    tally[l.kind.startsWith('missing') ? 'missing' : l.kind.startsWith('embedded') ? 'embedded' : 'system']++;
    const key = l.base + (l.weak ? ' (weak)' : '');
    if (!unique.has(key)) unique.set(key, { base: l.base, kind: l.kind, refs: [] });
    if (!unique.get(key).refs.includes(l.from)) unique.get(key).refs.push(l.from);
  }
  return {
    ok: true, binaries,
    linksTotal: all.length,
    tally,
    missing: [...unique.values()].filter((u) => u.kind.startsWith('missing')),
    unique: [...unique.values()].sort((a, b) => a.kind.localeCompare(b.kind) || a.base.localeCompare(b.base)),
  };
}
