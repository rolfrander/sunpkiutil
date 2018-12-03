package org.pvv.rolfn.pkiutil;
import sun.security.pkcs10.PKCS10;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.PKIXExtensions;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertInfo;
 
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Vector;
 

public class CertInfoFactory {
	private static final int numBits = 64;
	
	public static final String idKp = "1.3.6.1.5.5.7.3";
	public static final ObjectIdentifier EKU_OCSP = oid(idKp + ".9");
	public static final ObjectIdentifier EKU_SERVER= oid(idKp + ".1");
	public static final ObjectIdentifier EKU_CLIENT= oid(idKp + ".2");
	public static final String SKI_OID = "2.5.29.14";
	
	private X509CertInfo certInfo = new X509CertInfo();
	private CertificateExtensions ext;
	
	private static final ObjectIdentifier oid(String id) {
		try {
			return new ObjectIdentifier(id);
		} catch (IOException e) {
			throw new RuntimeException("invalid oid: "+id);
		}
	}
	
	public static CertInfoFactory newFactory() throws CertificateException, IOException {
		return new CertInfoFactory();
	}

	protected CertInfoFactory() throws CertificateException, IOException {
		certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(numBits, new SecureRandom())));
		certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		isNotCa();
	}

	public X509CertInfo build() {
		return certInfo;
	}

	private CertificateExtensions getExt() {
		if(ext == null) {
			ext = new CertificateExtensions();
		}
		return ext;
	}
	
	public void isCa(int len) throws CertificateException, IOException {
		basicConstraints(true, len);
	}
	
	public void isNotCa() throws CertificateException, IOException {
		basicConstraints(false, 0);
	}
	
	private void basicConstraints(boolean ca, int len) throws CertificateException, IOException {
	  getExt().set(BasicConstraintsExtension.IDENT, new BasicConstraintsExtension(Boolean.TRUE, ca, len));
	}

	public void keyIdentifier(PublicKey key) throws NoSuchAlgorithmException, CertificateException, IOException {
	  MessageDigest sha1 = MessageDigest.getInstance("SHA1");
	  byte[] ski = sha1.digest(key.getEncoded());
	  getExt().set(SubjectKeyIdentifierExtension.IDENT, new SubjectKeyIdentifierExtension(ski));
	}

	public void keyUsage(String... attributes) throws IOException, CertificateException {
	  KeyUsageExtension ku = new KeyUsageExtension();
	  for(String a: attributes) {
	    ku.set(a, Boolean.TRUE);
	  }
	  getExt().set(KeyUsageExtension.IDENT, ku);
	}

	public void extendedKeyUsage(ObjectIdentifier... attributes) throws CertificateException, IOException {
	  Vector<ObjectIdentifier> oids = new Vector<ObjectIdentifier>();
	  Collections.addAll(oids, attributes);
	  getExt().set(ExtendedKeyUsageExtension.IDENT, new ExtendedKeyUsageExtension(oids));
	}

	public void copyIssuer(X509Certificate caCert) throws CertificateException, IOException {
		Principal subjectDN = caCert.getSubjectDN();
		setIssuerName(subjectDN);
		byte[] caSKIBytes = caCert.getExtensionValue(PKIXExtensions.SubjectKey_Id.toString());
		if(caSKIBytes != null) {
			KeyIdentifier caKeyIdentifier = new KeyIdentifier(caSKIBytes);
			AuthorityKeyIdentifierExtension aki = new AuthorityKeyIdentifierExtension(caKeyIdentifier, null, null);
			getExt().set(AuthorityKeyIdentifierExtension.IDENT, aki);
		}
	}

	public void setIssuerName(Principal subjectDN) throws CertificateException, IOException {
		certInfo.set(X509CertInfo.ISSUER, subjectDN);
	}

	public void setValidity(int days) throws CertificateException, IOException {
		Date validFrom = new Date();
		long validDays = days * 24 * 60L * 60L * 1000L;
		Date validTo = new Date(validFrom.getTime() + validDays);
		certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(validFrom, validTo));
	}
	
	public void copyCsr(PKCS10 pkcs10) throws CertificateException, IOException,
	NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		setSubjectName(pkcs10.getSubjectName());
		setPublicKey(pkcs10.getSubjectPublicKeyInfo());
	}

	public void setPublicKey(PublicKey publicKey) throws CertificateException, IOException, NoSuchAlgorithmException {
		certInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
		keyIdentifier(publicKey);
	}

	public void setSubjectName(Principal owner) throws CertificateException, IOException {
		certInfo.set(X509CertInfo.SUBJECT, owner);
	}
	
	public void setAlgorithm(AlgorithmId algorithm) throws CertificateException, IOException {
		certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithm));
	}
}
