package org.simple.mail.client;

import lombok.Setter;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import org.simple.mail.error.DecryptPrivateKeyInfoException;
import org.simple.mail.util.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.util.Objects;
import java.util.Optional;

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

    public int process() throws IOException, CryptoException, OperatorCreationException {
        String command = request.getCommand();
        channel.sendRequest(request);
        response = channel.receiveResponse();
        if (Objects.nonNull(response)) {
            handleResponse(command);
            return 0;
        } else return -1;
    }

    private void handleResponse(String command) throws IOException, OperatorCreationException, CryptoException {
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

    private void doDataResponse() throws CryptoException, OperatorCreationException, IOException {
        System.out.println("Send: ");
        BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
        StringBuilder emailBuilder = new StringBuilder();
        String line;

        do {
            line = user.readLine();
            emailBuilder.append(line).append("\n");
        } while (line.compareTo(Mail.END_MAIL) != 0);

        // Encrypt email and AES key
        Optional<String> encryptedEmail = processEncryptEmail(user, emailBuilder.toString());

        if (encryptedEmail.isPresent()) {
            // Send email package
            channel.sendRequest(new Request(encryptedEmail.get()));
            channel.sendRequest(new Request(Command.END_MAIL));
            response = channel.receiveResponse();
            System.out.println(response.craftToString());
        }
    }

    private void doListResponse() throws IOException {
        StringBuilder builder = new StringBuilder();
        int numberOfMail = Integer.parseInt(response.getNotice());
        for (int i = 0; i < numberOfMail; i++)
            builder.append(channel.receiveLine());
        System.out.println(builder);
    }

    private void doRetrieveResponse() throws IOException, InvalidCipherTextException, OperatorCreationException {
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

        Optional<String> decryptedEmail = decryptEmailProcess(user, emailContent);
        decryptedEmail.ifPresent(System.out::println);
    }

    private Optional<String> processEncryptEmail(BufferedReader user, String emailContent) throws OperatorCreationException, CryptoException, IOException {
        // Get keys
        RSAUtil rsaCryptor = new RSAUtil();

        System.out.println("Path to recipient's public key:");
        String recipientPublicKeyPath = user.readLine();
        RSAKeyParameters recipientPublicKey;
        try {
            recipientPublicKey = rsaCryptor.getPublicKey(recipientPublicKeyPath);
        } catch (IOException e) {
            System.out.println("Error: File not found.");
            return Optional.empty();
        }

        System.out.println("Path to your private key:");
        String userPrivateKeyPath = user.readLine();

        System.out.println("Password for using private key:");
        String privateKeyPassword = user.readLine();
        RSAKeyParameters userPrivateKey;
        try {
            userPrivateKey = rsaCryptor.getPrivateKey(userPrivateKeyPath, privateKeyPassword);
        } catch (IOException e1) {
            System.out.println("Error: File not found.");
            return Optional.empty();
        } catch (DecryptPrivateKeyInfoException e2) {
            System.out.println("Cannot get private key. Maybe wrong password.");
            return Optional.empty();
        }

        return Optional.of(encryptEmail(emailContent, rsaCryptor, recipientPublicKey, userPrivateKey));
    }

    private String encryptEmail(String emailContent, RSAUtil rsaCryptor, RSAKeyParameters recipientPublicKey, RSAKeyParameters userPrivateKey) throws CryptoException {
        // Generate AES key
        AESUtil aesCryptor = new AESUtil();
        KeyParameter aesKey = aesCryptor.getKey(16);
        // Encrypt email with AES key
        String encryptedEmail = aesCryptor.encryptString(aesKey, emailContent);

        // Encrypt AES key with RSA public key
        byte[] encryptedAesKeyBytes = rsaCryptor.encryptBytes(recipientPublicKey, aesKey.getKey());
        String encryptedAesKey = Base64.toBase64String(encryptedAesKeyBytes);

        // Sign the entire message including the encrypted AES key
        String messageToSign = "KEY::" + encryptedAesKey + "\nBODY::" + encryptedEmail;
        SignatureUtil signOperator = new SignatureUtil();
        String signature = signOperator.signString(userPrivateKey, messageToSign);

        // Package email
        return SIG_HEADER + signature + "\n" +
                KEY + encryptedAesKey + "\n" +
                BODY + encryptedEmail;
    }

    private Optional<String> decryptEmailProcess(BufferedReader user, String emailContent) throws IOException, OperatorCreationException, InvalidCipherTextException {
        // Get keys
        RSAUtil rsaCryptor = new RSAUtil();

        System.out.println("Path to sender's public key:");
        String senderPublicKeyPath = user.readLine();
        RSAKeyParameters senderPublicKey;
        try {
            senderPublicKey = rsaCryptor.getPublicKey(senderPublicKeyPath);
        } catch (IOException e) {
            System.out.println("Error: File not found.");
            return Optional.empty();
        }

        System.out.println("Path to your private key:");
        String userPrivateKeyPath = user.readLine();

        System.out.println("Password for using private key:");
        String privateKeyPassword = user.readLine();
        RSAKeyParameters userPrivateKey;
        try {
            userPrivateKey = rsaCryptor.getPrivateKey(userPrivateKeyPath, privateKeyPassword);
        } catch (IOException e1) {
            System.out.println("Error: File not found.");
            return Optional.empty();
        } catch (DecryptPrivateKeyInfoException e2) {
            System.out.println("Cannot get private key. Maybe wrong password.");
            return Optional.empty();
        }
        return Optional.ofNullable(decryptEmail(emailContent, rsaCryptor, senderPublicKey, userPrivateKey));
    }

    private String decryptEmail(String emailContent, RSAUtil rsaCryptor, RSAKeyParameters senderPublicKey, RSAKeyParameters userPrivateKey) throws InvalidCipherTextException, UnsupportedEncodingException {
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

        // Verify signature
        SignatureUtil verifyOperator = new SignatureUtil();
        if (Objects.nonNull(bodyPart)) {
            String messageToVerify = "KEY::" + keyPart + "\nBODY::" + bodyPart;
            if (verifyOperator.verifyString(senderPublicKey, messageToVerify, sigPart)) {
                // Decrypt AES key
                byte[] aesKeyBytes = new byte[0];
                if (Objects.nonNull(keyPart))
                    aesKeyBytes = rsaCryptor.decryptBytes(userPrivateKey, Base64.decode(keyPart));

                // Decrypt email content
                AESUtil aesCryptor = new AESUtil();
                KeyParameter aesKey = new KeyParameter(aesKeyBytes);
                String decryptedEmail = aesCryptor.decryptString(aesKey, bodyPart);

                return leftPart.append(decryptedEmail).toString();
            } else
                System.out.println("Email is not authentic");
        }

        return null;
    }
}
