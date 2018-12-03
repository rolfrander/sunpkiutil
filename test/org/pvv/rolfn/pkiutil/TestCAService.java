package org.pvv.rolfn.pkiutil;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Base64.Encoder;

import org.junit.jupiter.api.Test;

class TestCAService {

	@Test
	void test() throws GeneralSecurityException, IOException {
		KeyPair caKeyPair = CertRequestFactory.getRSAKeyPair();
		CAService ca = new CAService("C=NO, O=rrn internett, OU=test, CN=CA-1", caKeyPair);
		X509Certificate cert = ca.generateCertificate(TestCertRequest.getPkcs10());
		// TODO virker ikke:
		// - subject alternative name
		// - authority key identifier
		System.out.println(cert.toString());
		printCert(cert);
	}
	
	private static void printCert(X509Certificate cert) throws CertificateEncodingException {
		 Encoder encoder = Base64.getEncoder();
		 String cert_begin = "-----BEGIN CERTIFICATE-----";
		 String end_cert = "-----END CERTIFICATE-----";

		 System.out.println(cert_begin);
		 byte[] derCert = cert.getEncoded();
		 System.out.println(new String(encoder.encode(derCert)));
		 System.out.println(end_cert);
	}

}
