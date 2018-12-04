package org.pvv.rolfn.pkiutil.bc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Locale;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import org.pvv.rolfn.pkiutil.CAService;

import sun.security.x509.SubjectKeyIdentifierExtension;

public class BcCAService implements CAService {
	public static int SERIAL_BITS       = 64;
	public static int VALID_DAYS_CA     = 3650;
	public static int VALID_DAYS_ENTITY = 90;
	public static String SIGN_ALG_NAME  = "SHA256WITHRSA";
	
	private X509Certificate caCert;
	private KeyPair caKeyPair;

	static {
		// denne trengs for å få JcaX509CertificateConverter til å virke lenger ned
		// usikker på hvorfor det er sånn
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public BcCAService(X509Certificate caCert, KeyPair caKeyPair) {
		this.caKeyPair = caKeyPair;
		this.caCert = caCert;
	}

	public BcCAService(String name, KeyPair caKeyPair) throws GeneralSecurityException, IOException {
		this.caKeyPair = caKeyPair;
		try {
			this.caCert = generateCaCertificate(name);
		} catch (OperatorException e) {
			throw new RuntimeException(e);
		}
	}
	
	public X509Certificate generateCertificate(byte csr[]) throws CertificateException, IOException, GeneralSecurityException {
		PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(csr);
		X500Name subject = pkcs10.getSubject();
		BigInteger serial = createSerial();

		Date validFrom = new Date();
		Date validTo = validTo(validFrom, VALID_DAYS_ENTITY);

		SubjectPublicKeyInfo publicKey = pkcs10.getSubjectPublicKeyInfo();
		
		Attribute attrs[] = pkcs10.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		for(Attribute a: attrs) {
			// TODO extensions
		}

		X500Name issuer = new X500Name(caCert.getIssuerX500Principal().getName(X500Principal.RFC1779));

		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial, validFrom, validTo, subject, publicKey);
		certBuilder.addExtension(Extension.keyUsage, false, 
				new KeyUsage(KeyUsage.dataEncipherment |
							 KeyUsage.keyAgreement     | 
							 KeyUsage.keyEncipherment  |
							 KeyUsage.digitalSignature));

		certBuilder.addExtension(Extension.extendedKeyUsage, false, 
				new ExtendedKeyUsage(new KeyPurposeId[] {
					KeyPurposeId.id_kp_clientAuth,
					KeyPurposeId.id_kp_serverAuth
				}));
		addSubjectKeyIdentifier(certBuilder, publicKey);
		byte[] extensionValue = caCert.getExtensionValue(Extension.subjectKeyIdentifier.toString());
		ASN1Primitive asn1ExtensionValue = JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
		byte[] authorityKeyIdentifier = ((ASN1OctetString)asn1ExtensionValue).getOctets();
		certBuilder.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(authorityKeyIdentifier));
		try {
			return sign(certBuilder);
		} catch (OperatorCreationException e) {
			throw new RuntimeException(e);
		}
	}

	protected X509Certificate generateCaCertificate(String name) throws IOException, OperatorException, CertificateException, GeneralSecurityException {
		X500Name dn = new X500Name(name);
		BigInteger serial = createSerial();
        
		Date validFrom = new Date();
		Date validTo = validTo(validFrom, VALID_DAYS_CA);
		
		SubjectPublicKeyInfo publicKey = keyPairToSubjectPublicKeyInfo(caKeyPair);
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(dn, serial, validFrom, validTo, dn, publicKey);
		certBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
		certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
		
		addSubjectKeyIdentifier(certBuilder, publicKey);

		return sign(certBuilder);
	}

	private void addSubjectKeyIdentifier(X509v3CertificateBuilder certBuilder, SubjectPublicKeyInfo publicKey)
			throws NoSuchAlgorithmException, CertIOException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        byte[] keyIdentifier = sha1.digest(publicKey.getPublicKeyData().getBytes());
		certBuilder.addExtension(Extension.subjectKeyIdentifier, false, new SubjectKeyIdentifier(keyIdentifier));
	}

	private Date validTo(Date validFrom, int validDays) {
		long milliseconds = validDays * 24 * 60L * 60L * 1000L;
		Date validTo = new Date(validFrom.getTime() + milliseconds);
		return validTo;
	}

	private X509Certificate sign(X509v3CertificateBuilder certBuilder) throws IOException, OperatorCreationException, CertificateException {
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIGN_ALG_NAME);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory.createKey(caKeyPair.getPrivate().getEncoded());
		ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);
        X509CertificateHolder certificateHolder = certBuilder.build(sigGen);
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
		return certificate;
	}

	private BigInteger createSerial() {
		return new BigInteger(SERIAL_BITS, new SecureRandom());
	}

	private SubjectPublicKeyInfo keyPairToSubjectPublicKeyInfo(KeyPair keyPair) {
		return SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPublic().getEncoded()));
	}
	
	public X509Certificate getCaCert() {
		return caCert;
	}

}
