package org.example;

import java.util.ArrayList;
import java.util.List;

public class ShiftCipher {
    /**
     * Encrypt a string by Shift cipher.
     *
     * @param plainText Message needs keeping secret.
     * @param k         The key to encrypt message.
     * @return A cipher message contains secretly plainText's content.
     */
    public String encrypt(String plainText, int k) {
        StringBuilder cipherText = new StringBuilder();
        char m, c;
        int mSeq, cSeq;
        plainText = plainText.toUpperCase();
        int length = plainText.length();
        for (int i = 0; i < length; i++) {
            m = plainText.charAt(i);
            if ('A' <= m && m <= 'Z') {
                mSeq = m - 'A';
                cSeq = (mSeq + k) % 26;
                c = (char) (cSeq + 'A');
                cipherText.append(c);
            } else cipherText.append(m);
        }
        return cipherText.toString();
    }

    /**
     * Decrypt a string encrypted by Shift cipher.
     *
     * @param cipherText Cipher message containing secretly encrypted content.
     * @param k          The key to decrypt message.
     * @return The decrypted original message.
     */
    public String decrypt(String cipherText, int k) {
        StringBuilder plainText = new StringBuilder();
        char m, c;
        int mSeq, cSeq;
        cipherText = cipherText.toUpperCase();
        int length = cipherText.length();
        for (int i = 0; i < length; i++) {
            c = cipherText.charAt(i);
            if ('A' <= c && c <= 'Z') {
                cSeq = c - 'A';
                mSeq = (cSeq - k + 26) % 26; // Ensure the result is positive
                m = (char) (mSeq + 'A');
                plainText.append(m);
            } else plainText.append(c);
        }
        return plainText.toString();
    }

    /**
     * Brute force attack to decrypt a string encrypted by Shift cipher.
     *
     * @param cipherText Cipher message containing secretly encrypted content.
     * @return A list of possible decrypted original messages.
     */
    public List<String> bruteForceAttack(String cipherText) {
        List<String> possibleMessages = new ArrayList<>();
        for (int k = 1; k <= 25; k++) {
            possibleMessages.add(decrypt(cipherText, k));
        }
        return possibleMessages;
    }
}
