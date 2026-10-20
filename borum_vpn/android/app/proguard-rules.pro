# R8 / ProGuard — borum VPN (com.borum.vpn)
# Les binaires tunnel (lib_*.so) sont des jniLibs exécutés via
# ProcessBuilder : R8 ne les affecte pas (et shrinkResources reste off).

# ── Bindings gomobile (vpnlib.aar) : JNI + reflection gobind ──────────────
-keep class vpnlib.** { *; }
-keepclassmembers class vpnlib.** { *; }

# ── Points d'entrée Android (manifeste) — conservés par AGP, redondance OK ─
-keep class com.borum.vpn.VPNApplication { *; }
-keep class com.borum.vpn.MainActivity { *; }
-keep class com.borum.vpn.AuthActivity { *; }
-keep class com.borum.vpn.BootReceiver { *; }
-keep class com.borum.vpn.TasVpnService { *; }

# ── JNI remonte des stacks via les noms de classes/ méthodes gobind ───────
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ── org.json (utilisé partout, pas de reflection nominative) ─────────────
-dontwarn org.json.**

# ── Réflexion interne (WifiManager.getWifiApState via getDeclaredMethod) ──
# reflection sur des méthodes du SDK : rien à keep côté app.

# ── Kotlin / coroutines / androidx ────────────────────────────────────────
-keepclassmembers class kotlinx.coroutines.** { *; }
-dontwarn kotlinx.coroutines.**
-dontwarn androidx.**

# ── Ressources R ──────────────────────────────────────────────────────────
-keepclassmembers class **.R$* { public static <fields>; }
