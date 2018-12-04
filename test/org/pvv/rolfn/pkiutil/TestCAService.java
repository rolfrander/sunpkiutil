package org.pvv.rolfn.pkiutil;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.io.PrintStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Base64.Encoder;

import org.junit.jupiter.api.Test;

import sun.security.pkcs10.PKCS10;

class TestCAService {
	public static final byte[] CRLF = new byte[] {'\r', '\n'};

	@Test
	void test() throws GeneralSecurityException, IOException {
		KeyPair caKeyPair = CertRequestFactory.getRSAKeyPair();
		CAService ca = new CAService("C=NO, O=rrn internett, OU=test, CN=CA-1", caKeyPair);
		PKCS10 req1 = TestCertRequest.getPkcs10();
		PKCS10 req2 = new PKCS10(req1.getEncoded());
		X509Certificate cert = ca.generateCertificate(req2);
		// TODO virker ikke:
		// - subject alternative name
		// - authority key identifier
		System.out.println(cert.toString());
		printCert(ca.getCaCert());
		printCert(cert);
	}

	private static String reqToString(PKCS10 req) {
		/*
        out.println("-----BEGIN NEW CERTIFICATE REQUEST-----");
        out.println(Base64.getMimeEncoder(64, CRLF).encodeToString(encoded));
        out.println("-----END NEW CERTIFICATE REQUEST-----");
        */
		return Base64.getEncoder().encodeToString(req.getEncoded());
	}
	
	private static void printCert(X509Certificate cert) throws CertificateEncodingException {
		Encoder encoder = Base64.getMimeEncoder(64, CRLF);
		String cert_begin = "-----BEGIN CERTIFICATE-----";
		String end_cert = "-----END CERTIFICATE-----";
		
		System.out.println(cert_begin);
		byte[] derCert = cert.getEncoded();
		System.out.println(new String(encoder.encode(derCert)));
		System.out.println(end_cert);
	}

}
