# kotlinx.serialization keeps generated serializers via @Serializable companions.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class dev.cyphernova.mobileops.** {
    *** Companion;
}
-keepclasseswithmembers class dev.cyphernova.mobileops.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# BouncyCastle registers providers reflectively; R8 cannot see those entry points.
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
