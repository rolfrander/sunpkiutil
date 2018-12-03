package org.pvv.rolfn.pkiutil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Base64;

import sun.security.pkcs10.PKCS10;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CAService {
	private X509Certificate caCert;
	private KeyPair caKeyPair;
	private AlgorithmId algorithm = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);

	public CAService(X509Certificate caCert, KeyPair caKeyPair) {
		this.caKeyPair = caKeyPair;
		this.caCert = caCert;
	}

	public CAService(String name, KeyPair caKeyPair) throws GeneralSecurityException, IOException {
		this.caKeyPair = caKeyPair;
		this.caCert = generateCaCertificate(name, caKeyPair);
	}
	
	protected X509Certificate generateCaCertificate(String name, KeyPair keyPair) throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		X500Name dn = new X500Name(name);
		CertInfoFactory cif = CertInfoFactory.newFactory();
		cif.isCa(0);
		cif.setValidity(3650);
		cif.setAlgorithm(algorithm);
		cif.setIssuerName(dn);
		cif.setSubjectName(dn);
		cif.setPublicKey(keyPair.getPublic());
		cif.keyUsage(
				KeyUsageExtension.KEY_CERTSIGN,
				KeyUsageExtension.CRL_SIGN);
		cif.extendedKeyUsage(CertInfoFactory.EKU_OCSP);
		X509CertInfo certInfo = cif.build();

		PrivateKey signingKey = keyPair.getPrivate();
		X509CertImpl newCert = sign(signingKey, certInfo);

		return newCert;
	}

	public X509Certificate generateCertificate(PKCS10 pkcs10) throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		CertInfoFactory cif = CertInfoFactory.newFactory();
		cif.isNotCa();
		cif.copyCsr(pkcs10);
		cif.copyIssuer(caCert);
		cif.setValidity(90);
		cif.setAlgorithm(algorithm);
		cif.keyUsage(
				KeyUsageExtension.DATA_ENCIPHERMENT,
				KeyUsageExtension.KEY_AGREEMENT,
				KeyUsageExtension.KEY_ENCIPHERMENT,
				KeyUsageExtension.DIGITAL_SIGNATURE);
		cif.extendedKeyUsage(CertInfoFactory.EKU_CLIENT, CertInfoFactory.EKU_SERVER);
		X509CertInfo certInfo = cif.build();

		PrivateKey signingKey = caKeyPair.getPrivate();
		X509CertImpl newCert = sign(signingKey, certInfo);

		return newCert;
	}

	private X509CertImpl sign(PrivateKey signingKey, X509CertInfo certInfo)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
			SignatureException, CertificateParsingException, IOException {
		// Create certificate and sign it
		X509CertImpl cert = new X509CertImpl(certInfo);
		cert.sign(signingKey, algorithm.getName());
		
		// Since the SHA1withRSA provider may have a different algorithm ID to what we think it should be,
		// we need to reset the algorithm ID, and resign the certificate
		AlgorithmId actualAlgorithm = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
		certInfo.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, actualAlgorithm);
		X509CertImpl newCert = new X509CertImpl(certInfo);
		newCert.sign(signingKey, actualAlgorithm.getName());
		return newCert;
	}
	
	static public PKCS10 decodeCsr(byte[] csr) throws SignatureException, NoSuchAlgorithmException, IOException {
		String request = new String(csr);
		String beginRequest = "-----BEGIN NEW CERTIFICATE REQUEST-----";
		String endRequest   = "-----END NEW CERTIFICATE REQUEST-----";
		request = request.replace(beginRequest, "");
		request = request.replace(endRequest, "");
		return new PKCS10(Base64.getMimeDecoder().decode(request));
	}

}
