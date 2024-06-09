package org.integrity.forward.util;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class HMacUtil {
    private static final String SALT = "99552371f24b195043148eb3e59d9fe84eb7efea";
    public static final int MAC_LENGTH = 256;

    public KeyParameter getSecretKey(String password) {
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), SALT.getBytes(), 1024);
        KeyParameter params = (KeyParameter) generator.generateDerivedParameters(MAC_LENGTH);

        return params;
    }

    public byte[] generateHMacBytes(KeyParameter key, byte[] byteData) {
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(key);
        hmac.update(byteData, 0, byteData.length);
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);

        return result;
    }

    public String generateHMacString(KeyParameter key, String input) throws UnsupportedEncodingException {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] outputBytes = generateHMacBytes(key, inputBytes);
        return Base64.toBase64String(outputBytes);
    }

    public boolean verifyHMacBytes(KeyParameter key, byte[] byteData, byte[] mic) {
        boolean isIntegrity = true;

        byte[] result = generateHMacBytes(key, byteData);
        if (result.length != mic.length)
            return false;

        for (int i = 0; i < result.length; i++) {
            if (result[i] != mic[i]) {
                isIntegrity = false;
                break;
            }
        }
        return isIntegrity;
    }

    public boolean verifyHMacString(KeyParameter key, String message, String mic) throws UnsupportedEncodingException {
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] micBytes = Base64.decode(mic);
        return verifyHMacBytes(key, messageBytes, micBytes);
    }

}
