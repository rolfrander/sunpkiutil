package org.pvv.rolfn.pkiutil;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import org.junit.jupiter.api.Test;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.DNSName;

class TestCertRequest {

	@Test
	void test() throws GeneralSecurityException, IOException {
		PKCS10 req = getPkcs10();
		req.print(System.out);
	}

	public static PKCS10 getPkcs10() throws NoSuchAlgorithmException, IOException, CertificateException, SignatureException,
			InvalidKeyException {
		CertRequestFactory crf = CertRequestFactory.newFactory(CertRequestFactory.getRSAKeyPair());
		crf.setName("C=NO, O=rolfn, OU=test, CN=foobar");
		crf.addSubjectAlternativeName(new DNSName("foobar.test.rolfn.pvv.org"));
		PKCS10 req = crf.build();
		return req;
	}

}
