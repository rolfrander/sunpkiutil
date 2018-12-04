package org.pvv.rolfn.pkiutil;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.Extension;
import sun.security.x509.GeneralNameInterface;

public interface CertRequestFactory {

	PKCS10 build()
			throws NoSuchAlgorithmException, CertificateException, SignatureException, IOException, InvalidKeyException;

	void setName(String distinguishedName) throws IOException;

	void addExtensionRequest(String name, Extension e) throws IOException;

	void addSubjectAlternativeName(GeneralNameInterface... names) throws IOException;

}