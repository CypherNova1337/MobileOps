# kotlinx.serialization keeps generated serializers via @Serializable companions.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class dev.cyphernova.mobileops.** {
    *** Companion;
}
-keepclasseswithmembers class dev.cyphernova.mobileops.** {
    kotlinx.serialization.KSerializer serializer(...);
}
