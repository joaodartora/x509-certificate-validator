package br.com.joaodartora.certificatevalidator.service;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.util.Collection;
import java.util.Set;

public class NewtonPKIXCertPathChecker extends PKIXCertPathChecker {

    private static final String NEWTON_CRITICAL_EXTENSION_OID = "1.2.840.113635.100.6.39";

    @Override
    public void init(boolean forward) {
    }

    @Override
    public boolean isForwardCheckingSupported() {
        return false;
    }

    @Override
    public Set<String> getSupportedExtensions() {
        return null;
    }

    /**
     * If Newton custom extension OID is present, it must be removed because
     * the extension isn't supported by the certificate validation lib.
     */
    @Override
    public void check(Certificate cert, Collection<String> unresolvedCritExts) throws CertPathValidatorException {
        if (!unresolvedCritExts.isEmpty() && unresolvedCritExts.contains(NEWTON_CRITICAL_EXTENSION_OID)) {
            unresolvedCritExts.remove(NEWTON_CRITICAL_EXTENSION_OID);
        }
    }
}
