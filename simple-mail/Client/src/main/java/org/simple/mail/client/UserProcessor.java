package org.simple.mail.client;

import lombok.Setter;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.simple.mail.util.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.util.Objects;

public class UserProcessor {
    private static final String SIG_HEADER = "SIG:";
    private static final String KEY = "KEY:";
    private static final String BODY = "BODY:";

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

    public int process() throws IOException, CryptoException, OperatorCreationException, PKCSException {
        String command = request.getCommand();
        channel.sendRequest(request);
        response = channel.receiveResponse();
        if (Objects.nonNull(response)) {
            handleResponse(command);
            return 0;
        } else return -1;
    }

    private void handleResponse(String command) throws IOException, OperatorCreationException, PKCSException, CryptoException {
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

    private void doDataResponse() throws CryptoException, OperatorCreationException, PKCSException, IOException {
        System.out.println("Send: ");
        BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder emailBuilder = new StringBuilder();
        String line;

        do {
            line = user.readLine();
            emailBuilder.append(line).append("\n");
        } while (line.compareTo(Mail.END_MAIL) != 0);

        System.out.println("Path to recipient's public key:");
        String recipientPublicKeyPath = user.readLine();

        System.out.println("Path to your private key:");
        String userPrivateKeyPath = user.readLine();

        System.out.println("Password for using private key:");
        String privateKeyPassword = user.readLine();

        // Encrypt email and AES key
        String encryptedEmail = encryptEmail(emailBuilder.toString(), recipientPublicKeyPath, userPrivateKeyPath, privateKeyPassword);

        // Send email package
        channel.sendRequest(new Request(encryptedEmail));
        channel.sendRequest(new Request(Command.END_MAIL));
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

    private void doRetrieveResponse() throws IOException, InvalidCipherTextException, OperatorCreationException, PKCSException {
        StringBuilder builder = new StringBuilder();
        String line;
        int leftBytes = Integer.parseInt(response.getNotice()) + 1;
        while (leftBytes > 0) {
            line = channel.receiveLine();
            builder.append(line);
            leftBytes = leftBytes - line.length();
        }
        String emailContent = builder.toString();

        BufferedReader user = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Path to sender's public key:");
        String senderPublicKeyPath = user.readLine();

        System.out.println("Path to your private key:");
        String userPrivateKeyPath = user.readLine();

        System.out.println("Password for using private key:");
        String privateKeyPassword = user.readLine();

        String decryptedEmail = decryptEmail(emailContent, senderPublicKeyPath, userPrivateKeyPath, privateKeyPassword);
        System.out.println(decryptedEmail);
    }

    private String encryptEmail(String emailContent, String recipientPublicKeyPath, String userPrivateKeyPath, String privateKeyPassword) throws CryptoException, OperatorCreationException, PKCSException {
        // Generate AES key
        AESUtil aesCryptor = new AESUtil();
        KeyParameter aesKey = aesCryptor.getKey(16);
        // Encrypt email with AES key
        String encryptedEmail = aesCryptor.encryptString(aesKey, emailContent);

        // Get keys
        RSAUtil rsaCryptor = new RSAUtil();
        RSAKeyParameters recipientPublicKey = rsaCryptor.getPublicKey(recipientPublicKeyPath);
        RSAKeyParameters userPrivateKey = rsaCryptor.getPrivateKey(userPrivateKeyPath, privateKeyPassword);

        // Encrypt AES key with RSA public key
        byte[] encryptedAesKeyBytes = rsaCryptor.encryptBytes(recipientPublicKey, aesKey.getKey());
        String encryptedAesKey = Base64.toBase64String(encryptedAesKeyBytes);

        // Sign the email content
        SignatureUtil signOperator = new SignatureUtil();
        String signature = signOperator.signString(userPrivateKey, encryptedEmail);

        // Package email
        StringBuilder encryptEmailBuilder = new StringBuilder();
        encryptEmailBuilder.append(SIG_HEADER).append(signature).append("\n")
                .append(KEY).append(encryptedAesKey).append("\n")
                .append(BODY).append(encryptedEmail);

        return encryptEmailBuilder.toString();
    }

    private String decryptEmail(String emailContent, String senderPublicKeyPath, String userPrivateKeyPath, String privateKeyPassword) throws OperatorCreationException, PKCSException, InvalidCipherTextException, UnsupportedEncodingException {
        // Parse the email components
        String[] lines = emailContent.split("\n");
        String sigPart = null;
        String keyPart = null;
        String bodyPart = null;
        StringBuilder leftPart = new StringBuilder();
        for (String line : lines) {
            if (line.startsWith(SIG_HEADER)) {
                sigPart = line.substring(SIG_HEADER.length()).trim();
            } else if (line.startsWith(KEY)) {
                keyPart = line.substring(KEY.length()).trim();
            } else if (line.startsWith(BODY)) {
                bodyPart = line.substring(BODY.length()).trim();
            } else {
                leftPart.append(line).append("\n");
            }
        }

        // Get keys
        RSAUtil rsaCryptor = new RSAUtil();
        RSAKeyParameters senderPublicKey = rsaCryptor.getPublicKey(senderPublicKeyPath);
        RSAKeyParameters userPrivateKey = rsaCryptor.getPrivateKey(userPrivateKeyPath, privateKeyPassword);

        // Verify signature
        SignatureUtil verifyOperator = new SignatureUtil();
        if (Objects.nonNull(bodyPart))
            if (verifyOperator.verifyString(senderPublicKey, bodyPart, sigPart))
                System.out.println("Message is authentic");
            else
                System.out.println("Message is not authentic");

        // Decrypt AES key
        byte[] aesKeyBytes = new byte[0];
        if (Objects.nonNull(keyPart))
            aesKeyBytes = rsaCryptor.decryptBytes(userPrivateKey, Base64.decode(keyPart));

        // Decrypt email content
        AESUtil aesCryptor = new AESUtil();
        KeyParameter aesKey = new KeyParameter(aesKeyBytes);
        String decryptedEmail = aesCryptor.decryptString(aesKey, bodyPart);

        return leftPart + decryptedEmail;
    }
}
