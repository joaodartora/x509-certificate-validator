package br.com.joaodartora.certificatevalidator.service;

import br.com.joaodartora.certificatevalidator.exception.CRLAccessLocationException;
import br.com.joaodartora.certificatevalidator.exception.CertificateVerificationException;
import br.com.joaodartora.certificatevalidator.exception.TrustException;
import br.com.joaodartora.certificatevalidator.stub.X509CertificateStub;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.X509Certificate;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class CertificateVerifierServiceTest {

    private final CRLVerifierService crlVerifierService;
    private final CertificateVerifierService certificateVerifierService;

    public CertificateVerifierServiceTest() {
        this.crlVerifierService = mock(CRLVerifierService.class);
        this.certificateVerifierService = new CertificateVerifierService(crlVerifierService);
    }

    @Test
    public void verifyCertificate_whenAllCertificatesAreOkAndCRLValidationIsTrue_shouldValidateCertificatesAndCRL() throws JoseException, CRLAccessLocationException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();
        X509Certificate leafCertificate = X509CertificateStub.buildLeafCertificate();

        var result = certificateVerifierService.verifyCertificate(leafCertificate, Set.of(rootCertificate, subCACertificate), true);

        assertAll(() -> assertEquals("[2.5.29.15, 2.5.29.19]", result.getTrustAnchor().getTrustedCert().getCriticalExtensionOIDs().toString()),
                () -> assertEquals("1.2.840.10045.4.3.3", result.getTrustAnchor().getTrustedCert().getSigAlgOID()),
                () -> assertEquals("SHA384withECDSA", result.getTrustAnchor().getTrustedCert().getSigAlgName())
        );
        verify(crlVerifierService, times(1)).verifyCertificates(anySet());
    }

    @Test
    public void verifyCertificate_whenAllCertificatesAreOkAndCRLValidationIsFalse_shouldValidateCertificatesButNotCRL() throws JoseException, CRLAccessLocationException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();
        X509Certificate leafCertificate = X509CertificateStub.buildLeafCertificate();

        doNothing().when(crlVerifierService).verifyCertificates(anySet());
        var result = certificateVerifierService.verifyCertificate(leafCertificate, Set.of(rootCertificate, subCACertificate), false);

        assertAll(() -> assertEquals("[2.5.29.15, 2.5.29.19]", result.getTrustAnchor().getTrustedCert().getCriticalExtensionOIDs().toString()),
                () -> assertEquals("1.2.840.10045.4.3.3", result.getTrustAnchor().getTrustedCert().getSigAlgOID()),
                () -> assertEquals("SHA384withECDSA", result.getTrustAnchor().getTrustedCert().getSigAlgName())
        );
        verify(crlVerifierService, never()).verifyCertificates(anySet());
    }

    @Test
    public void verifyCertificate_whenCertificateIsNull_shouldThrowCertificateVerificationExceptionWithMessage() throws JoseException, CRLAccessLocationException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();

        var result = assertThrows(CertificateVerificationException.class,
                () -> certificateVerifierService.verifyCertificate(null, Set.of(rootCertificate, subCACertificate), false));

        assertEquals("The certificate is null.", result.getMessage());
        verify(crlVerifierService, never()).verifyCertificates(anySet());
    }

    @Test
    public void verifyCertificate_whenCertificateHasExpired_shouldThrowCertificateVerificationExceptionWithMessage() throws JoseException, CRLAccessLocationException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();
        X509Certificate expiredCertificate = X509CertificateStub.buildExpiredCertificate();

        var result = assertThrows(CertificateVerificationException.class,
                () -> certificateVerifierService.verifyCertificate(expiredCertificate, Set.of(rootCertificate, subCACertificate), false));

        assertAll(() -> assertEquals("Error verifying certificate: EMAILADDRESS=teste@johnjohn.com.br, CN=johnjohn.com.br, OU=teste, O=johnjohn, C=Porto Alegre", result.getMessage()),
                () -> assertTrue(result.getCause().getMessage().startsWith("The certificate expired on: ")),
                () -> assertTrue(result.getCause() instanceof CertificateVerificationException)
        );
        verify(crlVerifierService, never()).verifyCertificates(anySet());
    }

    @Test
    public void verifyCertificate_whenCertificateIsSelfSigned_shouldThrowCertificateVerificationExceptionWithMessage() throws JoseException, CRLAccessLocationException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();

        var result = assertThrows(CertificateVerificationException.class,
                () -> certificateVerifierService.verifyCertificate(rootCertificate, Set.of(rootCertificate, subCACertificate), false));

        assertAll(() -> assertTrue(result.getMessage().startsWith("Error verifying certificate: ")),
                () -> assertEquals("The certificate is self-signed.", result.getCause().getMessage()),
                () -> assertTrue(result.getCause() instanceof CertificateVerificationException)
        );
        verify(crlVerifierService, never()).verifyCertificates(anySet());
    }

    @Test
    public void verifyCertificate_whenCertificateHasAErrorBuildingCertificationPath_shouldThrowCertificateVerificationExceptionWithMessage() throws JoseException, CRLAccessLocationException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();
        X509Certificate testLeafCertificate = X509CertificateStub.buildTestLeafCertificate();

        var result = assertThrows(CertificateVerificationException.class,
                () -> certificateVerifierService.verifyCertificate(testLeafCertificate, Set.of(rootCertificate, subCACertificate), false));

        assertAll(() -> assertTrue(result.getMessage().startsWith("Error building certification path:")),
                () -> assertEquals("No issuer certificate for certificate in certification path found.", result.getCause().getMessage()),
                () -> assertTrue(result.getCause() instanceof CertPathBuilderException)
        );
        verify(crlVerifierService, never()).verifyCertificates(anySet());
    }

    @Test
    public void verifyCertificate_whenCertificateHasAInvalidAlgorithm_shouldThrowCertificateVerificationExceptionWithMessage() throws JoseException, CRLAccessLocationException {
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();
        X509Certificate leafCertificate = X509CertificateStub.buildLeafCertificate();

        var result = assertThrows(CertificateVerificationException.class,
                () -> certificateVerifierService.verifyCertificate(leafCertificate, Set.of(leafCertificate, subCACertificate), false));

        assertAll(() -> assertTrue(result.getMessage().startsWith("No CA has been found: ")),
                () -> assertEquals("No root CA has been found for this certificate", result.getCause().getMessage()),
                () -> assertTrue(result.getCause() instanceof InvalidAlgorithmParameterException)
        );
        verify(crlVerifierService, never()).verifyCertificates(anySet());
    }

    @Test
    public void verifyCertificate_whenCRLVerifierThrowsException_shouldCatchAndThrowHandledExceptionWithMessage() throws JoseException, CRLAccessLocationException {
        X509Certificate rootCertificate = X509CertificateStub.buildRootCertificate();
        X509Certificate subCACertificate = X509CertificateStub.buildSubCACertificate();
        X509Certificate leafCertificate = X509CertificateStub.buildLeafCertificate();

        doThrow(CRLAccessLocationException.class).when(crlVerifierService).verifyCertificates(anySet());

        var result = assertThrows(CertificateVerificationException.class,
                () -> certificateVerifierService.verifyCertificate(leafCertificate, Set.of(rootCertificate, subCACertificate), true));

        assertAll(() -> assertTrue(result.getMessage().startsWith("Error verifying certificate: ")),
                () -> assertEquals("Cannot trust on this certificate chain", result.getCause().getMessage()),
                () -> assertTrue(result.getCause() instanceof TrustException)
        );
        verify(crlVerifierService, times(1)).verifyCertificates(anySet());
    }
}
