package org.simple.mail.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.simple.mail.error.DecryptPrivateKeyInfoException;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.Security;
import java.util.Objects;

public class RSAUtil {

    public RSAUtil() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public RSAKeyParameters getPrivateKey(String keyFile, String password)
            throws OperatorCreationException, IOException, DecryptPrivateKeyInfoException {
        try (FileReader reader = new FileReader(Paths.get(keyFile).toAbsolutePath().toFile());
             PEMParser pemParser = new PEMParser(reader)) {
            Object keyPair = pemParser.readObject();
            PrivateKeyInfo keyInfo = null;
            if (keyPair instanceof PKCS8EncryptedPrivateKeyInfo) {
                JceOpenSSLPKCS8DecryptorProviderBuilder jce =
                        new JceOpenSSLPKCS8DecryptorProviderBuilder();
                jce.setProvider(new BouncyCastleProvider());
                InputDecryptorProvider decProv = jce.build(password.toCharArray());
                try {
                    keyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyPair).decryptPrivateKeyInfo(decProv);
                } catch (PKCSException e) {
                    throw new DecryptPrivateKeyInfoException(e.getMessage());
                }
            } else if (keyPair instanceof PrivateKeyInfo) {
                keyInfo = (PrivateKeyInfo) keyPair;
            }
            if (Objects.nonNull(keyInfo)) {
                RSAKeyParameters privateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(keyInfo);
                return privateKey;
            }
        }
        return null;
    }

    public RSAKeyParameters getPublicKey(String certFile) throws IOException {
        try (FileReader reader = new FileReader(Paths.get(certFile).toAbsolutePath().toFile());
             PEMParser pemParser = new PEMParser(reader)) {
            X509CertificateHolder certificate;
            certificate = (X509CertificateHolder) pemParser.readObject();
            RSAKeyParameters publicKey = (RSAKeyParameters) PublicKeyFactory.createKey(
                    certificate.getSubjectPublicKeyInfo()
            );
            return publicKey;
        }
    }

    public byte[] encryptBytes(RSAKeyParameters publicKey, byte[] plainBytes) throws InvalidCipherTextException {
        OAEPEncoding cipher = new OAEPEncoding(new RSAEngine());
        cipher.init(true, publicKey);
        return cipher.processBlock(plainBytes, 0, plainBytes.length);
    }

    public byte[] decryptBytes(RSAKeyParameters privateKey, byte[] cipherBytes) throws InvalidCipherTextException {
        OAEPEncoding cipher = new OAEPEncoding(new RSAEngine());
        cipher.init(false, privateKey);
        return cipher.processBlock(cipherBytes, 0, cipherBytes.length);
    }
}
