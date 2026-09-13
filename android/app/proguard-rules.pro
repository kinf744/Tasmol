# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.

# WebView
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# Keep VPNApplication and its methods
-keep class com.vpnapp.VPNApplication { *; }

# Keep WebAppInterface
-keep class com.vpnapp.WebAppInterface { *; }

# Keep MainActivity
-keep class com.vpnapp.MainActivity { *; }

# Keep VPNService
-keep class com.vpnapp.VPNService { *; }

# Keep BootReceiver
-keep class com.vpnapp.BootReceiver { *; }

# Keep R classes
-keepclassmembers class **.R$* {
    public static <fields>;
}

# Keep BuildConfig
-keep class com.vpnapp.BuildConfig { *; }

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