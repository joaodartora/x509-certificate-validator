package br.com.joaodartora.certificatevalidator.client;

import br.com.joaodartora.certificatevalidator.exception.CRLClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;

@Component
public class CRLClient {

    private static final Logger logger = LoggerFactory.getLogger(CRLClient.class);
    private static final String HTTP_PREFIX = "http://";
    private static final String HTTPS_PREFIX = "https://";
    private static final String CERTIFICATE_TYPE = "X.509";

    public X509CRL downloadCRL(String crlURL) throws CertificateException, CRLException, CRLClientException, MalformedURLException {
        if (crlURL.startsWith(HTTP_PREFIX) || crlURL.startsWith(HTTPS_PREFIX)) {
            return downloadCRLFromWeb(crlURL);
        } else {
            throw new CRLClientException("Cannot download CRL from certificate distribution point: " + crlURL);
        }
    }

    private static X509CRL downloadCRLFromWeb(String crlUrl) throws CertificateException, CRLException, CRLClientException, MalformedURLException {
        URL url = new URL(crlUrl);
        try (InputStream crlStream = url.openStream()) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
            return (X509CRL) certificateFactory.generateCRL(crlStream);
        } catch (IOException exception) {
            logger.error("Error when trying to establish connection with CRL endpoint {}", crlUrl, exception);
            throw new CRLClientException("Couldn't open remote endpoint: " + crlUrl);
        }
    }
}
