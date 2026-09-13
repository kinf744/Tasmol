# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# WebView
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Keep application classes
-keep class com.ephang.vpn.VPNApplication { *; }
-keep class com.ephang.vpn.MainActivity { *; }
-keep class com.ephang.vpn.BootReceiver { *; }

# Keep TasVpnService and BinaryManager (VPN data plane)
-keep class com.ephang.vpn.TasVpnService { *; }
-keep class com.ephang.vpn.BinaryManager { *; }

# Keep gomobile bindings (vpnlib.aar) - accessed via JNI/reflection
-keep class vpnlib.** { *; }

# Keep R classes
-keepclassmembers class **.R$* {
    public static <fields>;
}

# Keep BuildConfig
-keep class com.ephang.vpn.BuildConfig { *; }

# Gson/JSON parsing (if used)
-keepattributes Signature
-keepattributes *Annotation*
-keep class sun.misc.Unsafe { *; }
-keep class com.google.gson.** { *; }

# OkHttp (if used)
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
-dontwarn okhttp3.**

# Kotlin coroutines
-keepclassmembers class kotlinx.coroutines.** { *; }