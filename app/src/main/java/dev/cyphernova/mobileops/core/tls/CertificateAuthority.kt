package dev.cyphernova.mobileops.core.tls

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Provider
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

/** A minted identity for one host, ready to hand to an SSL context. */
data class LeafIdentity(val certificate: X509Certificate, val privateKey: PrivateKey)

/**
 * The local certificate authority that signs the certificates interception presents.
 *
 * The CA key never leaves the device and lives in an app-private PKCS12 keystore. Only the
 * public certificate is exported, because that is the part a device has to trust — anyone
 * holding the private key could impersonate any site to a device trusting this CA, which is
 * exactly why it stays put.
 */
class CertificateAuthority(private val directory: File) {

    private val leafCache = ConcurrentHashMap<String, LeafIdentity>()

    @Volatile private var caCertificate: X509Certificate? = null
    @Volatile private var caKey: PrivateKey? = null

    val certificate: X509Certificate? get() = caCertificate
    val isReady: Boolean get() = caCertificate != null && caKey != null

    private val keystoreFile: File get() = File(directory, KEYSTORE_NAME)
    val exportedCertificateFile: File get() = File(directory, EXPORT_NAME)

    /** Loads the existing CA, generating one on first use. */
    suspend fun initialise(): X509Certificate = withContext(Dispatchers.IO) {
        ensureProvider()
        directory.mkdirs()

        caCertificate?.let { return@withContext it }

        if (keystoreFile.exists()) {
            runCatching { loadExisting() }.getOrNull()?.let { return@withContext it }
        }
        generateAndStore()
    }

    private fun loadExisting(): X509Certificate {
        val store = KeyStore.getInstance("PKCS12").apply {
            keystoreFile.inputStream().use { load(it, KEYSTORE_PASSWORD) }
        }
        val certificate = store.getCertificate(CA_ALIAS) as X509Certificate
        val key = store.getKey(CA_ALIAS, KEYSTORE_PASSWORD) as PrivateKey
        caCertificate = certificate
        caKey = key
        writeExport(certificate)
        return certificate
    }

    private fun generateAndStore(): X509Certificate {
        val keyPair = generateKeyPair()
        val now = System.currentTimeMillis()
        val name = X500Name("CN=$CA_COMMON_NAME, O=$CA_ORGANISATION")

        val builder = JcaX509v3CertificateBuilder(
            name,
            BigInteger(SERIAL_BITS, SecureRandom()),
            Date(now - BACKDATE_MS),
            Date(now + CA_VALIDITY_MS),
            name,
            keyPair.public,
        ).apply {
            addExtension(Extension.basicConstraints, true, BasicConstraints(0))
            addExtension(
                Extension.keyUsage,
                true,
                KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign or KeyUsage.digitalSignature),
            )
            addExtension(
                Extension.subjectKeyIdentifier,
                false,
                JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.public),
            )
        }

        val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
            .setProvider(bouncyCastle)
            .build(keyPair.private)
        val certificate = JcaX509CertificateConverter()
            .setProvider(bouncyCastle)
            .getCertificate(builder.build(signer))

        KeyStore.getInstance("PKCS12").apply {
            load(null, KEYSTORE_PASSWORD)
            setKeyEntry(CA_ALIAS, keyPair.private, KEYSTORE_PASSWORD, arrayOf(certificate))
            keystoreFile.outputStream().use { store(it, KEYSTORE_PASSWORD) }
        }

        caCertificate = certificate
        caKey = keyPair.private
        writeExport(certificate)
        return certificate
    }

    /**
     * Mints a certificate for one host, cached so a repeat visit reuses it — a fresh certificate
     * per connection would defeat session resumption and make the interception obvious.
     */
    fun leafFor(hostname: String): LeafIdentity? {
        val ca = caCertificate ?: return null
        val signingKey = caKey ?: return null

        return leafCache.getOrPut(hostname.lowercase()) {
            val keyPair = generateKeyPair()
            val now = System.currentTimeMillis()

            val builder = JcaX509v3CertificateBuilder(
                // Taken from the encoded form, not from the string: rendering a DN to text and
                // reparsing it reverses the RDN order, and a chain is built by matching this
                // issuer against the CA's subject byte for byte.
                X500Name.getInstance(ca.subjectX500Principal.encoded),
                BigInteger(SERIAL_BITS, SecureRandom()),
                Date(now - BACKDATE_MS),
                Date(now + LEAF_VALIDITY_MS),
                X500Name("CN=$hostname"),
                keyPair.public,
            ).apply {
                addExtension(Extension.basicConstraints, true, BasicConstraints(false))
                addExtension(
                    Extension.keyUsage,
                    true,
                    KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment),
                )
                addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth),
                )
                // Modern clients ignore CN entirely and match on SAN, so this is the field that
                // decides whether the certificate is accepted.
                addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    GeneralNames(GeneralName(generalNameType(hostname), hostname)),
                )
            }

            val signer = JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .setProvider(bouncyCastle)
                .build(signingKey)

            LeafIdentity(
                certificate = JcaX509CertificateConverter()
                    .setProvider(bouncyCastle)
                    .getCertificate(builder.build(signer)),
                privateKey = keyPair.private,
            )
        }
    }

    /** The CA certificate as PEM, which is what a device expects when importing a trust anchor. */
    fun exportPem(): String? {
        val certificate = caCertificate ?: return null
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(certificate.encoded)
        return "-----BEGIN CERTIFICATE-----\n$encoded\n-----END CERTIFICATE-----\n"
    }

    /**
     * The filename Android's system trust store keys on: the subject hash, then `.0`. Only
     * useful with root, but it is the piece people always have to look up.
     */
    fun systemTrustStoreName(): String? {
        val certificate = caCertificate ?: return null
        return "%08x.0".format(opensslSubjectHash(certificate))
    }

    private fun writeExport(certificate: X509Certificate) {
        runCatching {
            val encoded = Base64.getMimeEncoder(64, "\n".toByteArray())
                .encodeToString(certificate.encoded)
            exportedCertificateFile.writeText(
                "-----BEGIN CERTIFICATE-----\n$encoded\n-----END CERTIFICATE-----\n",
            )
        }
    }

    private fun generateKeyPair(): KeyPair =
        // Platform RSA key generation is fine and considerably faster than BouncyCastle's;
        // only certificate signing needs the full provider.
        KeyPairGenerator.getInstance("RSA").apply {
            initialize(KEY_BITS, SecureRandom())
        }.generateKeyPair()

    /** An IP literal has to go in as an IP SAN; a name goes in as a DNS SAN. */
    private fun generalNameType(host: String): Int =
        if (host.matches(IPV4)) GeneralName.iPAddress else GeneralName.dNSName

    private fun opensslSubjectHash(certificate: X509Certificate): Int {
        val digest = java.security.MessageDigest.getInstance("SHA-1")
            .digest(certificate.subjectX500Principal.encoded)
        return (digest[0].toInt() and 0xFF) or
            ((digest[1].toInt() and 0xFF) shl 8) or
            ((digest[2].toInt() and 0xFF) shl 16) or
            ((digest[3].toInt() and 0xFF) shl 24)
    }

    companion object {
        const val CA_COMMON_NAME = "MobileOps Interception CA"
        const val CA_ORGANISATION = "MobileOps"

        private const val KEYSTORE_NAME = "intercept-ca.p12"
        private const val EXPORT_NAME = "MobileOps-CA.pem"
        private val KEYSTORE_PASSWORD = "mobileops".toCharArray()
        private const val CA_ALIAS = "ca"
        private const val KEY_BITS = 2048
        private const val SERIAL_BITS = 64
        private const val SIGNATURE_ALGORITHM = "SHA256withRSA"
        private const val CA_VALIDITY_MS = 365L * 24 * 60 * 60 * 1000
        private const val LEAF_VALIDITY_MS = 90L * 24 * 60 * 60 * 1000
        /** Clock skew between this device and the servers being contacted is routine. */
        private const val BACKDATE_MS = 24L * 60 * 60 * 1000
        private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

        /**
         * Our own BouncyCastle instance, used directly rather than registered.
         *
         * Android already ships a cut-down BouncyCastle registered under the name "BC", which
         * has no SHA256withRSA signer. Asking for a provider *by name* therefore resolves to
         * the platform's stripped copy, and registering over it either fails silently — a
         * provider of that name already exists — or displaces crypto the rest of the system is
         * relying on. Holding the instance and passing it to each builder sidesteps the name
         * lookup entirely and leaves the platform's providers untouched.
         */
        val bouncyCastle: Provider = BouncyCastleProvider()

        fun ensureProvider() {
            // Nothing to register: the provider is passed to each builder directly.
        }
    }
}
