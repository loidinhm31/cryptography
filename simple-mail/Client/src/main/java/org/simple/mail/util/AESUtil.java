package org.simple.mail.util;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;

public class AESUtil {
    protected static final int IV_LENGTH = 16;

    public AESUtil() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public KeyParameter getKey(int keySize) {
        if (keySize != 16 && keySize != 24 && keySize != 32) {
            throw new IllegalArgumentException("Key length must be 128, 192, or 256 bits");
        }
        byte[] byteArr = new byte[keySize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(byteArr);
        return new KeyParameter(byteArr);
    }

    public byte[] encryptBytes(KeyParameter key, byte[] plainBytes) throws InvalidCipherTextException {
        PaddedBufferedBlockCipher encryptCipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(AESEngine.newInstance())
        );
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        ParametersWithIV parameterIV = new ParametersWithIV(key, iv);
        encryptCipher.init(true, parameterIV);

        byte[] output = new byte[encryptCipher.getOutputSize(plainBytes.length)];
        int len = encryptCipher.processBytes(plainBytes, 0, plainBytes.length, output, 0);
        len += encryptCipher.doFinal(output, len);

        byte[] encrypted = new byte[IV_LENGTH + len];
        System.arraycopy(iv, 0, encrypted, 0, IV_LENGTH);
        System.arraycopy(output, 0, encrypted, IV_LENGTH, len);

        return encrypted;
    }

    public String encryptString(KeyParameter key, String plainText) throws InvalidCipherTextException {
        return Base64.toBase64String(encryptBytes(key, plainText.getBytes(StandardCharsets.UTF_8)));
    }

    public byte[] decryptBytes(KeyParameter key, byte[] cipherBytes) throws InvalidCipherTextException {
        PaddedBufferedBlockCipher decryptCipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(AESEngine.newInstance())
        );
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(cipherBytes, 0, iv, 0, IV_LENGTH);
        ParametersWithIV parameterIV = new ParametersWithIV(key, iv);
        decryptCipher.init(false, parameterIV);

        byte[] cipherData = new byte[cipherBytes.length - IV_LENGTH];
        System.arraycopy(cipherBytes, IV_LENGTH, cipherData, 0, cipherData.length);

        byte[] output = new byte[decryptCipher.getOutputSize(cipherData.length)];
        int len = decryptCipher.processBytes(cipherData, 0, cipherData.length, output, 0);
        len += decryptCipher.doFinal(output, len);

        byte[] decrypted = new byte[len];
        System.arraycopy(output, 0, decrypted, 0, len);

        return decrypted;
    }

    public String decryptString(KeyParameter key, String cipherText) throws InvalidCipherTextException {
        byte[] cipherBytes = Base64.decode(cipherText);
        return new String(decryptBytes(key, cipherBytes), StandardCharsets.UTF_8);
    }
}
