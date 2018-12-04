package org.pvv.rolfn.pkiutil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

public interface CAService {

	X509Certificate getCaCert();
	X509Certificate generateCertificate(byte[] csr) throws GeneralSecurityException, IOException ;

}