package org.pvv.rolfn.pkiutil;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;

import sun.security.pkcs10.PKCS10;
import sun.security.pkcs10.PKCS10Attributes;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.Extension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNameInterface;
import sun.security.x509.GeneralNames;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;

/**
 * A factory for sun.security.pkcs certificate requests.
 * @author norolnes
 *
 */
public class CertRequestFactory {
	
	private KeyPair keyPair;
	private PKCS10Attributes attr;
	private X500Name name;
	private CertificateExtensions ext;
	private GeneralNames names;
	
	public static CertRequestFactory newFactory(KeyPair kp) {
		return new CertRequestFactory(kp);
	}
	
	protected CertRequestFactory(KeyPair kp) {
		this.keyPair = kp;
		this.attr = new PKCS10Attributes();
	}

	public PKCS10 build() throws NoSuchAlgorithmException, CertificateException, SignatureException, IOException, InvalidKeyException {
		PKCS10 req = new PKCS10(keyPair.getPublic(), attr);
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(keyPair.getPrivate());
		req.encodeAndSign(name, signature);
		return req;
	}
	
	public void setName(String distinguishedName) throws IOException {
		this.name = new X500Name(distinguishedName);
	}

	public void addExtensionRequest(String name, Extension e) throws IOException {
		if(ext == null) {
			ext = new CertificateExtensions();
		}
		ext.set(name, e);
	}

	private GeneralNames getSAN() throws IOException {
		if(names == null) {
			names = new GeneralNames();
			SubjectAlternativeNameExtension san = new SubjectAlternativeNameExtension(names);
			addExtensionRequest(SubjectAlternativeNameExtension.NAME, san);
		}
		return names;
	}
	
	public void addSubjectAlternativeName(GeneralNameInterface name) throws IOException {
		getSAN().add(new GeneralName(name));
	}
	
    public static KeyPair getRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA");
        int keysize = 2048;
        kpGenerator.initialize(keysize);
        return kpGenerator.generateKeyPair();
    }
}
