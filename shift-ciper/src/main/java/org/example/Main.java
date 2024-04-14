package org.example;

import java.util.Arrays;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        ShiftCipher utils = new ShiftCipher();
        String encryptedData = utils.encrypt("HELLO WORLD", 3);

        System.out.println(encryptedData);

        String decryptedData = utils.decrypt(encryptedData, 3);

        System.out.println(decryptedData);

        List<String> bruteForceAttackResult = utils.bruteForceAttack(encryptedData);

        System.out.println(Arrays.toString(bruteForceAttackResult.toArray()));
    }
}