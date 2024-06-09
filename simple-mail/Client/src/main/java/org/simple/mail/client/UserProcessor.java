package org.simple.mail.client;

import lombok.Setter;
import org.simple.mail.util.*;

import javax.crypto.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class UserProcessor {
    @Setter
    private Request request;
    @Setter
    private Response response;
    private TcpChannel channel;

    public UserProcessor(Socket sock) {
        try {
            channel = new TcpChannel(sock);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public int process() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        String command = request.getCommand();
        channel.sendRequest(request);
        response = channel.receiveResponse();
        if (response != null) {
            handleResponse(command);
            return 0;
        } else return -1;
    }

    private void handleResponse(String command) throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        System.out.println("Receive: " + response.craftToString());

        String returnCode = response.getCode();
        if (returnCode.compareTo(Response.SUCCESS) == 0) {
            if (command.compareToIgnoreCase(Command.DATA) == 0)
                doDataResponse();
            else if (command.compareToIgnoreCase(Command.LIST) == 0)
                doListResponse();
            else if (command.compareToIgnoreCase(Command.RETRIEVE) == 0)
                doRetrieveResponse();
        }
    }

    private void doDataResponse() throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidKeySpecException, BadPaddingException, InvalidKeyException {
        System.out.println("Send: ");
        BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder emailBuilder = new StringBuilder();
        String line;

        do {
            line = user.readLine();
        } while (line.compareTo(Mail.END_MAIL) != 0);

        String emailContent = emailBuilder.toString();

        System.out.println("Enter path to recipient's public key (.pem):");
        String recipientPublicKeyPath = user.readLine();

        System.out.println("Enter path to your private key (.pem):");
        String userPrivateKeyPath = user.readLine();

        System.out.println("Enter password for your private key:");
        String privateKeyPassword = user.readLine();

        // Encrypt email and AES key
        String encryptedEmail = encryptEmail(emailContent, recipientPublicKeyPath);

        // Send encrypted email
        channel.sendRequest(new Request(encryptedEmail));
        response = channel.receiveResponse();
        System.out.println(response.craftToString());
    }

    private void doListResponse() throws IOException {
        StringBuilder builder = new StringBuilder();
        int numberOfMail = Integer.parseInt(response.getNotice());
        for (int i = 0; i < numberOfMail; i++)
            builder.append(channel.receiveLine());
        System.out.println(builder);
    }

    private void doRetrieveResponse() throws IOException {
        StringBuilder builder = new StringBuilder();
        String line;
        int leftBytes = Integer.parseInt(response.getNotice()) + 1;
        while (leftBytes > 0) {
            line = channel.receiveLine();
            builder.append(line);
            leftBytes = leftBytes - line.length();
        }
        System.out.println(builder);
    }

    private String encryptEmail(String emailContent, String recipientPublicKeyPath) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt email with AES key
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedEmailBytes = aesCipher.doFinal(emailContent.getBytes());
        String encryptedEmail = Base64.getEncoder().encodeToString(encryptedEmailBytes);

        // Encrypt AES key with RSA public key
        byte[] publicKeyBytes = Files.readAllBytes(Paths.get(recipientPublicKeyPath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(spec);

        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedAesKeyBytes = rsaCipher.doFinal(aesKey.getEncoded());
        String encryptedAesKey = Base64.getEncoder().encodeToString(encryptedAesKeyBytes);

        // Combine encrypted email and encrypted AES key
        return encryptedEmail + ":" + encryptedAesKey;
    }
}
