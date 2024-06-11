package org.simple.mail.util;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

public class SignatureUtil {
    public byte[] signBytes(RSAKeyParameters key, byte[] inputBytes) throws DataLengthException, CryptoException {
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(true, key);
        signer.update(inputBytes, 0, inputBytes.length);
        return signer.generateSignature();
    }

    public String signString(RSAKeyParameters key, String input) throws DataLengthException, CryptoException {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] outputBytes = signBytes(key, inputBytes);
        return Base64.toBase64String(outputBytes);
    }

    public boolean verifyBytes(RSAKeyParameters key, byte inputBytes[], byte[] signature) {
        RSADigestSigner verifier = new RSADigestSigner(new SHA256Digest());
        verifier.init(false, key);
        verifier.update(inputBytes, 0, inputBytes.length);
        return verifier.verifySignature(signature);
    }

    public boolean verifyString(RSAKeyParameters key, String input, String signature) throws UnsupportedEncodingException {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] sigBytes = Base64.decode(signature);
        return verifyBytes(key, inputBytes, sigBytes);
    }
}
