# Mobile Application VAPT Reference

Testing methodology for Android and iOS apps, with special focus on Flutter-based applications.

## Table of Contents
1. [Initial Analysis](#initial-analysis)
2. [Flutter App Testing](#flutter-app-testing)
3. [Root & Emulator Detection Bypass](#root--emulator-detection-bypass)
4. [SSL Pinning Bypass](#ssl-pinning-bypass)
5. [Frida Instrumentation](#frida-instrumentation)
6. [Static Analysis](#static-analysis)
7. [Dynamic Analysis](#dynamic-analysis)
8. [Data Storage Testing](#data-storage-testing)
9. [iOS-Specific Testing](#ios-specific-testing)

---

## Initial Analysis

### APK Analysis (Android)
```bash
# Decompile APK
apktool d target.apk -o target_decompiled

# Extract classes
jadx target.apk -d target_jadx

# Get package info
aapt dump badging target.apk

# List permissions
aapt dump permissions target.apk

# Check for native libraries
ls target_decompiled/lib/arm64-v8a/
# Look for: libflutter.so (Flutter), libapp.so (Flutter compiled Dart)
# libreactnativejni.so (React Native), libts.so (Talsec/freeRASP)
```

### Identify Protection Mechanisms
Look for these in decompiled code:
- **freeRASP / Talsec**: `libts.so` in native libs, `com.aheaditec.talsec` in code
- **RootBeer**: `com.scottyab.rootbeer` package
- **SafetyNet / Play Integrity**: `com.google.android.gms.safetynet`
- **SSL Pinning**: OkHttp `CertificatePinner`, custom `TrustManager`, Flutter `SecurityContext`
- **Obfuscation**: ProGuard/R8 (class names like `a.b.c`), DexGuard

### Quick Wins
Before deep analysis, check for:
- Hardcoded secrets in `strings.xml`, `AndroidManifest.xml`, `local.properties`
- API keys in decompiled code (`grep -ri "api_key\|api-key\|apikey\|secret\|password\|token"`)
- Debug flags (`android:debuggable="true"`)
- Backup allowed (`android:allowBackup="true"`)
- Exported components (activities, services, receivers, providers)

---

## Flutter App Testing

Flutter apps compile Dart to native code (`libapp.so`), making traditional Java/Kotlin decompilation useless for the core logic.

### Identification
- `libflutter.so` + `libapp.so` in native libs
- `io.flutter` packages in manifest
- Flutter engine version in `libflutter.so` strings

### Flutter-Specific Analysis
```bash
# Extract Dart snapshot info
strings libapp.so | grep -i "dart\|flutter\|http\|api\|token\|key\|secret\|url"

# Use reFlutter for snapshot analysis (if compatible with Flutter version)
reflutter target.apk

# Dart snapshot tooling
# blutter (for newer Flutter versions)
python3 blutter.py target_decompiled/lib/arm64-v8a/libapp.so output_dir
```

### Network Interception for Flutter
Flutter uses its own HTTP client (dart:io), which does NOT use system proxy settings or system CA store by default.

**Options for intercepting Flutter traffic:**
1. **reFlutter** — patch `libflutter.so` to use system proxy and trust user CA
2. **ProxyDroid / iptables** — force all traffic through proxy at OS level
3. **Frida** — hook `dart:io` HTTP client to add proxy and disable cert checks
4. **VPN-based proxy** — apps like HTTP Toolkit that set up a VPN

---

## Root & Emulator Detection Bypass

### freeRASP (Talsec) Bypass
freeRASP checks: root, emulator, hooks (Frida/Xposed), ADB, debug, tampering, device binding.

**Frida bypass approach:**
```javascript
// Hook Talsec callback to suppress threat detection
Java.perform(function() {
    // Intercept the threat callback
    var ThreatListener = Java.use('com.aheaditec.talsec_security.security.api.ThreatListener');
    
    // Override onRootDetected
    ThreatListener.onRootDetected.implementation = function() {
        console.log('[*] Root detection suppressed');
        // Don't call original — swallow the callback
    };
    
    // Override onEmulatorDetected  
    ThreatListener.onEmulatorDetected.implementation = function() {
        console.log('[*] Emulator detection suppressed');
    };
    
    // Override onHookDetected
    ThreatListener.onHookDetected.implementation = function() {
        console.log('[*] Hook detection suppressed');
    };
    
    // Override onDebuggerDetected
    ThreatListener.onDebuggerDetected.implementation = function() {
        console.log('[*] Debugger detection suppressed');
    };
});
```

**Note:** freeRASP's native library (`libts.so`) performs some checks at native level. If Java-level hooks don't work, you may need to:
- Patch `libts.so` directly (binary patching)
- Hook native functions via Frida's `Interceptor.attach` on `libts.so` exports
- Use Frida's early instrumentation (`--no-pause` with spawn)

### RootBeer Bypass
```javascript
Java.perform(function() {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log('[*] RootBeer.isRooted() bypassed');
        return false;
    };
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
        return false;
    };
    RootBeer.detectRootManagementApps.implementation = function() {
        return false;
    };
});
```

### Generic Root Detection Bypass
```javascript
Java.perform(function() {
    // Hook common file checks
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ['su', 'Superuser', 'magisk', 'busybox', '/system/xbin/su', '/system/app/Superuser'];
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                console.log('[*] Root file check bypassed: ' + path);
                return false;
            }
        }
        return this.exists();
    };

    // Hook Runtime.exec for su checks
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
            console.log('[*] Runtime.exec bypassed: ' + cmd);
            throw Java.use('java.io.IOException').$new('not found');
        }
        return this.exec(cmd);
    };
    
    // Hook Build properties for emulator detection
    var Build = Java.use('android.os.Build');
    Build.FINGERPRINT.value = 'google/walleye/walleye:8.1.0/OPM1.171019.021/4565141:user/release-keys';
    Build.MODEL.value = 'Pixel 2';
    Build.MANUFACTURER.value = 'Google';
    Build.BRAND.value = 'google';
    Build.PRODUCT.value = 'walleye';
    Build.HARDWARE.value = 'walleye';
});
```

---

## SSL Pinning Bypass

### Universal Bypass (Java layer)
```javascript
Java.perform(function() {
    // OkHttp CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[*] OkHttp pinning bypassed for: ' + hostname);
        };
    } catch(e) {}

    // TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[*] TrustManager bypassed for: ' + host);
            return untrustedChain;
        };
    } catch(e) {}

    // WebViewClient
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log('[*] WebView SSL error ignored');
            handler.proceed();
        };
    } catch(e) {}
});
```

### Flutter SSL Pinning Bypass
```javascript
// Hook dart:io SecurityContext to trust all certs
// This requires knowing the Flutter engine offsets — use reFlutter or:
var module = Process.findModuleByName('libflutter.so');
// Find ssl_crypto_x509_session_verify_cert_chain
// Patch to always return true
```

The most reliable method for Flutter is **reFlutter** — it patches `libflutter.so` to disable SSL verification entirely.

---

## Frida Instrumentation

### Setup
```bash
# Start frida-server on device
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Connect (USB)
frida -U -f com.target.app -l script.js --no-pause

# Connect (remote/emulator)
frida -H 127.0.0.1:27042 -f com.target.app -l script.js --no-pause

# For MEmu emulator
adb connect 127.0.0.1:21503
frida -H 127.0.0.1:21503 -f com.target.app -l script.js
```

### Useful Frida Snippets

**Enumerate loaded classes:**
```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes('security') || className.includes('root') || className.includes('tamper')) {
                console.log('[*] Security class: ' + className);
            }
        },
        onComplete: function() { console.log('[*] Done'); }
    });
});
```

**Hook all methods in a class:**
```javascript
Java.perform(function() {
    var targetClass = Java.use('com.target.SecurityManager');
    var methods = targetClass.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log('[*] Method: ' + method.getName());
    });
});
```

**Intercept HTTP requests:**
```javascript
Java.perform(function() {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function() {
        console.log('[*] URL: ' + this.toString());
        return this.openConnection();
    };
});
```

---

## Static Analysis

### AndroidManifest.xml Checks
- `android:debuggable="true"` → High
- `android:allowBackup="true"` → Medium
- `android:usesCleartextTraffic="true"` → Medium
- Exported components without permissions → Medium
- Custom permissions with `protectionLevel="normal"` → Low
- Deep link schemes (potential for link hijacking)

### Code Analysis
- Hardcoded credentials, API keys, tokens
- Insecure crypto (ECB mode, static IV, hardcoded keys)
- Insecure random (`java.util.Random` instead of `SecureRandom`)
- WebView with JS enabled + loadUrl from untrusted input
- SQL injection in ContentProviders
- Path traversal in FileProviders

---

## Dynamic Analysis

### Network Traffic
- Proxy all traffic through Burp Suite
- Look for: cleartext credentials, tokens in URLs, PII in request/response
- Check certificate validation — does the app work with Burp CA?
- API endpoint discovery from live traffic

### Data Storage
```bash
# Check shared preferences
adb shell cat /data/data/com.target.app/shared_prefs/*.xml

# Check databases
adb shell ls /data/data/com.target.app/databases/
adb pull /data/data/com.target.app/databases/app.db
sqlite3 app.db ".tables"

# Check for sensitive data in logs
adb logcat | grep -i "token\|password\|key\|secret\|session"

# Check external storage
adb shell ls /sdcard/Android/data/com.target.app/

# Check cache
adb shell ls /data/data/com.target.app/cache/
```

### Clipboard & Screenshot
- Does the app allow screenshots on sensitive screens?
- Does it clear clipboard after paste on sensitive fields?
- Does it mask sensitive input fields?

---

## iOS-Specific Testing

### IPA Analysis
```bash
# Unzip IPA
unzip target.ipa -d target_extracted

# Check for encryption
otool -l Payload/Target.app/Target | grep crypt

# Dump decrypted binary (on jailbroken device)
frida-ios-dump -u target.bundle.id

# Check Info.plist
plutil -p Payload/Target.app/Info.plist

# Look for ATS exceptions (App Transport Security)
# NSAllowsArbitraryLoads = true → cleartext traffic allowed
```

### iOS Keychain
```bash
# Dump keychain items (jailbroken device with keychain-dumper)
./keychain_dumper

# Check protection classes
# kSecAttrAccessibleWhenUnlocked (acceptable)
# kSecAttrAccessibleAlways (finding: insecure keychain storage)
```

### iOS-Specific Checks
- Universal links / deep links configuration
- ATS (App Transport Security) exceptions
- Binary protections: PIE, ARC, stack canaries
- Jailbreak detection and bypass
- Pasteboard leakage
- Background screenshot protection
