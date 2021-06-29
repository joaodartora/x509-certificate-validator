package br.com.joaodartora.certificatevalidator.service;

import br.com.joaodartora.certificatevalidator.exception.CRLAccessLocationException;
import br.com.joaodartora.certificatevalidator.exception.CertificateVerificationException;
import br.com.joaodartora.certificatevalidator.exception.TrustException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Class for building a certification chain for given certificate and verifying
 * it. Relies on a set of root CA certificates and intermediate certificates
 * that will be used for building the certification chain. The verification
 * process assumes that all self-signed certificates in the set are trusted
 * root CA certificates and all other certificates in the set are intermediate
 * certificates.
 * <p>
 * The entire backbone of this class was taken from the project https://github.com/nandosola/trantor-certificate-verifier
 *
 * @see <a href="https://nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-chain-and-verify-clr-with-bouncy-castle/">X.509 Certificate Validation in Java: Build and Verify Chain and Verify CLR with Bouncy Castle</a>
 */
@Service
public final class CertificateVerifierService {

    private static final Logger logger = LoggerFactory.getLogger(CertificateVerifierService.class);
    private static final String BOUNCY_CASTLE_PROVIDER_NAME = "BC";
    private final CRLVerifierService crlVerifierService;

    public CertificateVerifierService(CRLVerifierService crlVerifierService) {
        this.crlVerifierService = crlVerifierService;
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Attempts to build a certification chain for given certificate and to verify
     * it. Relies on a set of root CA certificates and intermediate certificates
     * that will be used for building the certification chain. The verification
     * process assumes that all self-signed certificates in the set are trusted
     * root CA certificates and all other certificates in the set are intermediate
     * certificates.
     *
     * @param certificate     - certificate for validation
     * @param additionalCerts - set of trusted root CA certificates that will be
     *                        used as "trust anchors" and intermediate CA certificates that will be
     *                        used as part of the certification chain. All self-signed certificates
     *                        are considered to be trusted root CA certificates. All the rest are
     *                        considered to be intermediate CA certificates.
     * @return the certification chain (if verification is successful)
     * @throws CertificateVerificationException - if the certification is not
     *                                          successful (e.g. certification path cannot be built or some
     *                                          certificate in the chain is expired or CRL checks are failed)
     */
    public PKIXCertPathBuilderResult verifyCertificate(X509Certificate certificate, Set<X509Certificate> additionalCerts, boolean verifyCrl) throws CertificateVerificationException, TrustException {
        if (certificate == null)
            throw new CertificateVerificationException("The certificate is null.");
        try {
            isExpired(certificate);
            if (isSelfSigned(certificate)) {
                throw new CertificateVerificationException("The certificate is self-signed.");
            }

            // Prepare a set of trusted root CA certificates and a set of certificates who need to be CRL verified.
            Set<X509Certificate> trustedRootCerts = new HashSet<>();
            Set<X509Certificate> crlToBeVerifiedCerts = new LinkedHashSet<>();

            for (X509Certificate additionalCert : additionalCerts) {
                if (isSelfSigned(additionalCert)) {
                    trustedRootCerts.add(additionalCert);
                } else {
                    crlToBeVerifiedCerts.add(additionalCert);
                }
            }

            // All non-root (leaf and intermediate) certificates must be CRL verified.
            // The leaf must be verified at last because if an intermediate certificate is untrusted, all certificates signed by him are untrusted too.
            crlToBeVerifiedCerts.add(certificate);

            logger.debug("Attempting to build the certification chain and verify it");
            PKIXCertPathBuilderResult verifiedCertificateChain = verifyCertificate(certificate, trustedRootCerts, additionalCerts);

            if (verifyCrl) verifyCertificateRevocationList(crlToBeVerifiedCerts);

            return verifiedCertificateChain;
        } catch (InvalidAlgorithmParameterException iapEx) {
            throw new CertificateVerificationException("No CA has been found: " + certificate.getSubjectX500Principal(), iapEx);
        } catch (CertPathBuilderException certPathEx) {
            throw new CertificateVerificationException("Error building certification path: " + certificate.getSubjectX500Principal(), certPathEx);
        } catch (Exception exception) {
            throw new CertificateVerificationException("Error verifying certificate: " + certificate.getSubjectX500Principal(), exception);
        }
    }

    private void verifyCertificateRevocationList(Set<X509Certificate> certificates) throws CertificateVerificationException, TrustException {
        try {
            logger.info("Verifying certificate revocation list for all non-root certificates");
            crlVerifierService.verifyCertificates(certificates);
        } catch (CRLAccessLocationException crlEx) {
            logger.error("Couldn't find CRL distribution points for some of the non-root certificates", crlEx);
            throw new TrustException("Cannot trust on this certificate chain", crlEx);
        }
    }

    private static void isExpired(X509Certificate certificate) {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException exception) {
            logger.error("This certificate expired on: {} ", certificate.getNotAfter(), exception);
            throw new CertificateVerificationException("The certificate expired on: " + certificate.getNotAfter());
        } catch (CertificateNotYetValidException exception) {
            logger.debug("This certificate is not yet valid, only will be valid after: {}", certificate.getNotBefore(), exception);
        }
    }

    private static boolean isSelfSigned(X509Certificate certificate) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException {
        try {
            // Try to verify certificate signature with its own public key
            PublicKey key = certificate.getPublicKey();
            certificate.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException sigEx) {
            return false; // Invalid signature or key --> not self-signed
        }
    }

    /**
     * Attempts to build a certification chain for given certificate and to verify
     * it. Relies on a set of root CA certificates (trust anchors) and a set of
     * intermediate certificates (to be used as part of the chain).
     *
     * @param certificate          - certificate for validation
     * @param allTrustedRootCerts  - set of trusted root CA certificates
     * @param allIntermediateCerts - set of intermediate certificates
     * @return the certification chain (if verification is successful)
     * @throws GeneralSecurityException - if the verification is not successful
     *                                  (e.g. certification path cannot be built or some certificate in the
     *                                  chain is expired)
     */
    private static PKIXCertPathBuilderResult verifyCertificate(X509Certificate certificate,
                                                               Set<X509Certificate> allTrustedRootCerts,
                                                               Set<X509Certificate> allIntermediateCerts) throws GeneralSecurityException {
        // Create the selector that specifies the starting certificate
        X509CertSelector certificateSelector = new X509CertSelector();
        certificateSelector.setCertificate(certificate);

        // Create the trust anchors (set of root CA certificates)
        Set<TrustAnchor> trustAnchors = allTrustedRootCerts.stream()
            .map(trustedRootCertificate -> new TrustAnchor(trustedRootCertificate, null))
            .collect(Collectors.toSet());

        // Configure the PKIX certificate builder algorithm parameters
        PKIXBuilderParameters pkixParams;
        try {
            pkixParams = new PKIXBuilderParameters(trustAnchors, certificateSelector);
        } catch (InvalidAlgorithmParameterException ex) {
            throw new InvalidAlgorithmParameterException("No root CA has been found for this certificate", ex);
        }

        // Disable CRL checks (this is done manually as additional step)
        pkixParams.setRevocationEnabled(false);

        // Add all certs to store so that the chain can be constructed
        pkixParams.addCertStore(createCertStore(certificate));
        pkixParams.addCertStore(createCertStore(allIntermediateCerts));
        pkixParams.addCertStore(createCertStore(allTrustedRootCerts));

        // Add custom path checker for Newton Certificates
        pkixParams.addCertPathChecker(new NewtonPKIXCertPathChecker());

        // Build and verify the certification chain
        CertPathBuilder builder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType(), BOUNCY_CASTLE_PROVIDER_NAME);
        return (PKIXCertPathBuilderResult) builder.build(pkixParams);
    }

    private static CertStore createCertStore(X509Certificate certificate)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        Set<X509Certificate> certificateSet = new HashSet<>(Set.of(certificate));
        return createCertStore(certificateSet);
    }

    private static CertStore createCertStore(Set<X509Certificate> certificateSet)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return CertStore.getInstance("Collection", new CollectionCertStoreParameters(certificateSet), BOUNCY_CASTLE_PROVIDER_NAME);
    }
}
