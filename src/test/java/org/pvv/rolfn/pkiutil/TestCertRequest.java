package org.pvv.rolfn.pkiutil;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import org.junit.jupiter.api.Test;
import org.pvv.rolfn.pkiutil.sun.SunCertRequestFactory;

import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attribute;
import sun.security.pkcs10.PKCS10Attributes;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.DNSName;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.SubjectAlternativeNameExtension;

class TestCertRequest {

	public static final String DN = "C=NO, O=rolfn, OU=test, CN=foobar";
	public static final String DNS = "foobar.test.rolfn.pvv.org";

	@Test
	void test() throws GeneralSecurityException, IOException {
		PKCS10 req = getPkcs10();
		req.print(System.out);

		PKCS10Attributes attr = req.getAttributes();
		assertEquals(DN, req.getSubjectName().toString());
		CertificateExtensions extensionRequest = (CertificateExtensions) ((PKCS10Attribute) attr.getAttribute(PKCS9Attribute.EXTENSION_REQUEST_OID.toString())).getAttributeValue();
		SubjectAlternativeNameExtension sanExtension = (SubjectAlternativeNameExtension)extensionRequest.get(SubjectAlternativeNameExtension.IDENT);
		GeneralNameInterface generalName = sanExtension.get(sanExtension.getElements().nextElement()).get(0).getName();
		assertEquals(DNS, ((DNSName)generalName).getName());
	}

	public static PKCS10 getPkcs10() throws NoSuchAlgorithmException, IOException, CertificateException, SignatureException,
			InvalidKeyException {
		CertRequestFactory crf = SunCertRequestFactory.newFactory(SunCertRequestFactory.getRSAKeyPair());
		crf.setName(DN);
		crf.addSubjectAlternativeName(new DNSName(DNS));
		PKCS10 req = crf.build();
		return req;
	}

}
