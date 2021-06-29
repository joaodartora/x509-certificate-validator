package br.com.joaodartora.certificatevalidator.service;

import br.com.joaodartora.certificatevalidator.client.CRLClient;
import br.com.joaodartora.certificatevalidator.exception.CRLAccessLocationException;
import br.com.joaodartora.certificatevalidator.exception.CRLClientException;
import br.com.joaodartora.certificatevalidator.exception.CertificateVerificationException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Service
public class CRLVerifierService {

    private static final Logger logger = LoggerFactory.getLogger(CRLVerifierService.class);
    private final CRLClient crlClient;

    public CRLVerifierService(CRLClient crlClient) {
        this.crlClient = crlClient;
    }

    /**
     * Extracts the CRL distribution points from the certificate (if available)
     * and checks the certificate revocation status against the CRLs coming from
     * the distribution points. Supports HTTP and HTTPS based URLs.
     *
     * @param certificates the certificates to be checked for revocation
     * @throws CertificateVerificationException if the certificate is revoked
     */
    public void verifyCertificates(Set<X509Certificate> certificates) throws CertificateVerificationException, CRLAccessLocationException {
        certificates.stream()
            .forEach(this::verifyCertificate);
    }

    private void verifyCertificate(X509Certificate certificate) {
        try {
            List<String> crlDistributionPoints = getAccessLocation(certificate);
            if (crlDistributionPoints.isEmpty()) {
                logger.error("Cannot found OCSP endpoint information for CRL validation on certificate {}", certificate.getSubjectX500Principal());
                throw new CRLAccessLocationException("OCSP endpoint information is missing");
            }
            for (String crlDp : crlDistributionPoints) {
                X509CRL crl = crlClient.downloadCRL(crlDp);
                if (crl.isRevoked(certificate)) {
                    logger.error("The certificate is revoked by CRL: {} ", crlDp);
                    throw new CertificateVerificationException("The certificate is revoked by CRL: " + crlDp);
                }
                logger.debug("Certificate looks fine and is not revoked by any CRL");
            }
        } catch (CRLClientException | CRLException ex) {
            throw new CertificateVerificationException("The client could not retrieve the CRL information", ex);
        } catch (Exception ex) {
            throw new CertificateVerificationException("Can not verify CRL for certificate: " + certificate.getSubjectX500Principal(), ex);
        }
    }

    /**
     * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
     * extension in a X.509 certificate. If CRL distribution point extension is
     * unavailable, returns an empty list.
     */
    private static List<String> getAccessLocation(X509Certificate certificate) throws CertificateException {
        byte[] crlDistributionPointsExtension = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        if (crlDistributionPointsExtension == null) return Collections.emptyList();

        List<String> crlUrls = new ArrayList<>();
        try {
            CRLDistPoint distributionPoint = getDistributionPointsFromExtension(crlDistributionPointsExtension);
            for (DistributionPoint distPoint : distributionPoint.getDistributionPoints()) {
                DistributionPointName distPointName = distPoint.getDistributionPoint();
                // Look for URIs in fullName
                if (distPointName != null && distPointName.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] generalNames = GeneralNames.getInstance(distPointName.getName()).getNames();
                    // Look for an URI
                    for (GeneralName generalName : generalNames) {
                        if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = DERIA5String.getInstance(generalName.getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
        } catch (IOException e) {
            logger.error("Found CRL attributes on distribution point, but couldn't read them. The certificate {} might be corrupted or tampered with", certificate.getSubjectX500Principal());
            throw new CertificateException("Found CRL attributes, but couldn't read them. The certificate might be corrupted or tampered with");
        }
        return crlUrls;
    }

    private static CRLDistPoint getDistributionPointsFromExtension(byte[] crlDistributionPointsExtension) throws IOException {
        ASN1InputStream asn1InStream = new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointsExtension));
        ASN1Primitive derObjectCrlDP = asn1InStream.readObject();
        DEROctetString derOctetStringCrlDP = (DEROctetString) derObjectCrlDP;
        byte[] crlDpExtensionOctets = derOctetStringCrlDP.getOctets();

        ASN1InputStream asn1InStream2 = new ASN1InputStream(new ByteArrayInputStream(crlDpExtensionOctets));
        ASN1Primitive derObjectCrlDP2 = asn1InStream2.readObject();
        return CRLDistPoint.getInstance(derObjectCrlDP2);
    }

}
