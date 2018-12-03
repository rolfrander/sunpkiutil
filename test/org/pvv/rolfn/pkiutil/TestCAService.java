package org.pvv.rolfn.pkiutil;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

class TestCAService {

	@Test
	void test() throws GeneralSecurityException, IOException {
		KeyPair caKeyPair = CertRequestFactory.getRSAKeyPair();
		CAService ca = new CAService("C=NO, O=rrn internett, OU=test, CN=CA-1", caKeyPair);
		X509Certificate cert = ca.generateCertificate(TestCertRequest.getPkcs10());
		System.out.println(cert.toString());
	}

}
