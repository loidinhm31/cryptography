package org.integrity.forward.util;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.StandardCharsets;

public class TestHMac {
    public final static String PASSWORD = "123456";
    private static final String SALT = "99552371f24b195043148eb3e59d9fe84eb7efea";
    public static final int MAC_LENGTH = 256;

    public static void main(String[] args) {
        PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(PASSWORD.toCharArray()), SALT.getBytes(), 1024);
        KeyParameter key = (KeyParameter) generator.generateDerivedParameters(MAC_LENGTH);

        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(key);

        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            builder.append("1234567890");
        }

        String input = builder.toString();
        byte[] byteData = input.getBytes(StandardCharsets.UTF_8);
        hmac.update(byteData, 0, byteData.length);
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        System.out.println("Hash1:" + Base64.toBase64String(result));
        System.out.println("Size: " + result.length);
        int leftBytes = byteData.length;

        for (int i = 0; leftBytes > 32; i++) {
            hmac.update(byteData, i * 32, 32);
            leftBytes = leftBytes - 32;
        }
        result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        System.out.println("Hash2:" + Base64.toBase64String(result));
        System.out.println("Size: " + result.length);
    }

}
