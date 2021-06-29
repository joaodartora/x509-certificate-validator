package br.com.joaodartora.certificatevalidator.service;

import br.com.joaodartora.certificatevalidator.exception.CRLAccessLocationException;
import br.com.joaodartora.certificatevalidator.client.CRLClient;
import br.com.joaodartora.certificatevalidator.exception.CRLClientException;
import br.com.joaodartora.certificatevalidator.exception.CertificateVerificationException;
import br.com.joaodartora.certificatevalidator.stub.X509CertificateStub;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CRLVerifierServiceTest {

    private final CRLClient crlClient;
    private final CRLVerifierService crlVerifierService;
    private final X509CRL x509CRL;

    public CRLVerifierServiceTest() {
        this.crlClient = mock(CRLClient.class);
        this.x509CRL = mock(X509CRL.class);
        this.crlVerifierService = new CRLVerifierService(crlClient);
    }

    @Test
    public void verifyCertificates_whenCertificateIsCorrect_shouldVerifyAndDontThrowAnyException() throws JoseException, MalformedURLException, CRLClientException, CertificateException, CRLException {
        X509Certificate leafCertificate = X509CertificateStub.buildLeafCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();

        when(crlClient.downloadCRL(anyString())).thenReturn(x509CRL);
        when(crlClient.downloadCRL(anyString())).thenReturn(x509CRL);
        when(x509CRL.isRevoked(any())).thenReturn(Boolean.FALSE);

        assertDoesNotThrow(() -> crlVerifierService.verifyCertificates(Set.of(subCACertificate, leafCertificate)));
    }

    @Test
    public void verifyCertificates_whenCertificateIsRevokedByCRL_shouldVerifyAndThrowCertificateVerificationExceptionWithMessage() throws JoseException, MalformedURLException, CRLClientException, CertificateException, CRLException {
        X509Certificate leafCertificate = X509CertificateStub.buildLeafCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();

        when(crlClient.downloadCRL(anyString())).thenReturn(x509CRL);
        when(crlClient.downloadCRL(anyString())).thenReturn(x509CRL);
        when(x509CRL.isRevoked(any())).thenReturn(Boolean.TRUE);

        Set<X509Certificate> certificates = new LinkedHashSet<>();
        certificates.add(subCACertificate);
        certificates.add(leafCertificate);

        var result = assertThrows(CertificateVerificationException.class, () -> crlVerifierService.verifyCertificates(certificates));

        assertAll(() -> assertTrue(result.getMessage().startsWith("Can not verify CRL for certificate: ")),
                () -> assertTrue(result.getCause().getMessage().startsWith("The certificate is revoked by CRL:"))
        );
    }

    @Test
    public void verifyCertificates_whenOneCertificateHasNoDistributionPoints_shouldThrowCertificateVerificationExceptionWithMessage() throws JoseException, MalformedURLException, CRLClientException, CertificateException, CRLException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();

        when(crlClient.downloadCRL(anyString())).thenReturn(x509CRL);
        when(x509CRL.isRevoked(any())).thenReturn(Boolean.FALSE);

        var result = assertThrows(CertificateVerificationException.class, () -> crlVerifierService.verifyCertificates(Set.of(subCACertificate, rootCertificate)));

        assertAll(() -> assertTrue(result.getMessage().startsWith("Can not verify CRL for certificate:")),
                () -> assertEquals("OCSP endpoint information is missing", result.getCause().getMessage()),
                () -> assertTrue(result.getCause() instanceof CRLAccessLocationException)
        );
    }

    @Test
    public void verifyCertificates_whenDownloadCRLThrowsCRLException_shouldCatchAndThrowHandledExceptionWithMessage() throws JoseException, MalformedURLException, CRLClientException, CertificateException, CRLException {
        X509Certificate leafCertificate = X509CertificateStub.buildLeafCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();

        when(crlClient.downloadCRL(anyString())).thenThrow(CRLException.class);
        var result = assertThrows(CertificateVerificationException.class, () -> crlVerifierService.verifyCertificates(Set.of(subCACertificate, leafCertificate)));

        assertAll(() -> assertEquals("The client could not retrieve the CRL information", result.getMessage()),
                () -> assertNull(result.getCause().getMessage()),
                () -> assertTrue(result.getCause() instanceof CRLException)
        );
    }

}
