package org.rsa.echo.client;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.rsa.echo.util.RSAUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Objects;

public class RSAEchoClient {
    private static final String SERVER_ADDR = "127.0.0.1";
    private static final int SERVER_PORT = 5000;

    public static void main(String[] args) {
        boolean isSecure = Boolean.FALSE;

        try (BufferedReader user = new BufferedReader(new InputStreamReader(System.in))) {
            // Import server's public key
            RSAUtil rsaCryptor = new RSAUtil();
            RSAKeyParameters serverPublicKey;
            String serverPublicKeyFile;
            System.out.print("Server certificate file: ");
            serverPublicKeyFile = user.readLine();
            serverPublicKey = rsaCryptor.getPublicKey(serverPublicKeyFile);

            // Connect to server
            InetAddress servAddr = InetAddress.getByName(SERVER_ADDR);
            try (Socket clientSocket = new Socket(servAddr, SERVER_PORT);
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()))
            ) {

                RSAKeyParameters clientPrivateKey = null;
                if (isSecure) {
                    // Import client's private key file
                    String clientPrivateKeyFile, keyPassword;
                    System.out.print("Client private key file: ");
                    clientPrivateKeyFile = user.readLine();
                    System.out.print("Password for using private key: ");
                    keyPassword = user.readLine();
                    clientPrivateKey = rsaCryptor.getPrivateKey(clientPrivateKeyFile, keyPassword);
                }

                String message, reply;

                while (true) {
                    System.out.print("Send to server: ");
                    message = user.readLine();
                    if (message.length() == 0)
                        break;

                    // Encrypt plain message with server's public key
                    message = rsaCryptor.encryptString(serverPublicKey, message);

                    // Send message to server
                    out.println(message);
                    out.flush();

                    // Receive message from server
                    reply = in.readLine();

                    if (isSecure && Objects.nonNull(clientPrivateKey)) {
                        // Decrypt message with client's private key
                        reply = rsaCryptor.decryptString(clientPrivateKey, reply);
                    }

                    System.out.println("Reply from Server:" + reply);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
