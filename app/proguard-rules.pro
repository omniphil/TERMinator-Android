# ProGuard rules for SyncTERM Android

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep NativeBridge class (JNI interface)
-keep class com.syncterm.android.NativeBridge { *; }

# Keep data classes used with SharedPreferences
-keep class com.syncterm.android.MainActivity$SavedConnection { *; }

# Keep ConnectionManager state enum (used in StateFlow)
-keep class com.syncterm.android.ConnectionManager$State { *; }

# Keep Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# Keep R8 from removing coroutine intrinsics
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# Preserve line numbers for debugging stack traces
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
