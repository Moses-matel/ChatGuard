# Keep Kotlinx Serialization generated serializers & @Serializable models
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class id.chatguard.core.model.**$$serializer { *; }
-keepclassmembers class id.chatguard.core.model.** {
    *** Companion;
}
-keepclasseswithmembers class id.chatguard.core.model.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep Room entities & DAOs
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keepclassmembers class id.chatguard.data.** { *; }

# Keep Android entry points
-keep class id.chatguard.ui.MainActivity { *; }
-keep class id.chatguard.stage1.** { *; }
-keep class id.chatguard.stage2.** { *; }

# Suppress harmless OkHttp/Conscrypt optional warnings
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
