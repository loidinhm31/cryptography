package org.simple.mail.util;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
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
        SecureRandom random = new SecureRandom();
        byte[] iv = random.generateSeed(IV_LENGTH);
        ParametersWithIV parameterIV = new ParametersWithIV(key, iv);
        encryptCipher.init(true, parameterIV);

        byte[] output = new byte[encryptCipher.getOutputSize(plainBytes.length)];
        int ret1 = encryptCipher.processBytes(plainBytes, 0, plainBytes.length, output, 0);
        int ret2 = encryptCipher.doFinal(output, ret1);
        byte[] result = new byte[IV_LENGTH + ret1 + ret2];
        System.arraycopy(iv, 0, result, 0, IV_LENGTH);
        System.arraycopy(output, 0, result, IV_LENGTH, result.length - IV_LENGTH);

        return output;
    }

    public String encryptString(KeyParameter key, String plainText) throws InvalidCipherTextException {
        String cipherText;
        cipherText = Base64.toBase64String(encryptBytes(key, plainText.getBytes(StandardCharsets.UTF_8)));
        return cipherText;
    }

    public byte[] decryptBytes(KeyParameter key, byte[] cipherBytes) throws InvalidCipherTextException {
        PaddedBufferedBlockCipher decryptCipher = new PaddedBufferedBlockCipher(
                CBCBlockCipher.newInstance(AESEngine.newInstance())
        );
        SecureRandom random = new SecureRandom();
        byte[] iv = random.generateSeed(IV_LENGTH);
        ParametersWithIV parameterIV = new ParametersWithIV(key, iv);
        decryptCipher.init(true, parameterIV);

        byte[] cipherData = new byte[cipherBytes.length - IV_LENGTH];
        System.arraycopy(cipherBytes, IV_LENGTH, cipherData, 0, cipherData.length);
        byte[] output = new byte[decryptCipher.getOutputSize(cipherData.length)];
        int ret1 = decryptCipher.processBytes(cipherData, 0, cipherData.length, output,
                0);
        int ret2 = decryptCipher.doFinal(output, ret1);
        byte[] result = new byte[ret1 + ret2];
        System.arraycopy(output, 0, result, 0, result.length);

        return output;
    }

    public String decryptString(KeyParameter key, String cipherText) throws InvalidCipherTextException {
        byte[] cipherBytes = Base64.decode(cipherText);
        return new String(decryptBytes(key, cipherBytes), StandardCharsets.UTF_8);
    }
}
