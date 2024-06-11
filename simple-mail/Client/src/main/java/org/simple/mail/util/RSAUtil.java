package org.simple.mail.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;


public class RSAUtil {

    public RSAKeyParameters getPrivateKey(String keyFile, String password)
            throws OperatorCreationException, PKCSException {
        RSAKeyParameters privateKey = null;
        PrivateKeyInfo keyInfo = null;
        try (FileReader reader = new FileReader(Paths.get(keyFile).toAbsolutePath().toFile());
             PEMParser pemParser = new PEMParser(reader)) {
            Object keyPair = pemParser.readObject();
            if (keyPair instanceof PKCS8EncryptedPrivateKeyInfo) {
                JceOpenSSLPKCS8DecryptorProviderBuilder jce =
                        new JceOpenSSLPKCS8DecryptorProviderBuilder();
                jce.setProvider(new BouncyCastleProvider());
                InputDecryptorProvider decProv = jce.build(password.toCharArray());
                keyInfo = ((PKCS8EncryptedPrivateKeyInfo) keyPair).decryptPrivateKeyInfo(decProv);
            } else if (keyPair instanceof PrivateKeyInfo) {
                keyInfo = (PrivateKeyInfo) keyPair;
            }
            if (Objects.nonNull(keyInfo))
                privateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(keyInfo);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public RSAKeyParameters getPublicKey(String certFile) {
        RSAKeyParameters publicKey = null;
        try (FileReader reader = new FileReader(Paths.get(certFile).toAbsolutePath().toFile());
             PEMParser pemParser = new PEMParser(reader)) {
            X509CertificateHolder certificate;
            certificate = (X509CertificateHolder) pemParser.readObject();
            publicKey = (RSAKeyParameters) PublicKeyFactory.createKey(
                    certificate.getSubjectPublicKeyInfo()
            );
        } catch (IOException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public byte[] encryptBytes(RSAKeyParameters publicKey, byte[] plainBytes) throws InvalidCipherTextException {
        OAEPEncoding cipher = new OAEPEncoding(new RSAEngine());
        cipher.init(true, publicKey);
        return cipher.processBlock(plainBytes, 0, plainBytes.length);
    }

}
