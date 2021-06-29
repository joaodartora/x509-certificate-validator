package br.com.joaodartora.certificatevalidator.exception;

public class TrustException extends RuntimeException {

    public TrustException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
