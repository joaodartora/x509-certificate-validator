package br.com.joaodartora.certificatevalidator.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(code = HttpStatus.UNAUTHORIZED, reason = "Error when trying to validate certificates")
public class CertificateVerificationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public CertificateVerificationException(String message) {
        super(message);
    }

    public CertificateVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
