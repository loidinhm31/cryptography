package org.rsa.echo.server;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.rsa.echo.util.RSAUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;

public class RSAEchoServer {
    private static final int SERVER_PORT = 5000;

    public static void main(String[] args) {
        boolean isSecure = Boolean.FALSE;

        try (ServerSocket servSocket = new ServerSocket(SERVER_PORT);
             BufferedReader user = new BufferedReader(new InputStreamReader(System.in))) {

            // Import server's private key
            RSAUtil rsaCryptor = new RSAUtil();
            RSAKeyParameters serverPrivateKey;
            String clientPublicKeyFile, serverPrivateKeyFile, keyPassword;

            System.out.print("Server private key file: ");
            serverPrivateKeyFile = user.readLine();
            System.out.print("Password for using private key: ");
            keyPassword = user.readLine();
            serverPrivateKey = rsaCryptor.getPrivateKey(serverPrivateKeyFile, keyPassword);

            while (true) {
                System.out.println("Waiting connection...");

                // Accept client connection
                Socket connSocket = servSocket.accept();
                System.out.println("Client:" + connSocket.getInetAddress().getHostAddress());

                RSAKeyParameters clientPublicKey = null;
                if (isSecure) {
                    // Import client's public key
                    System.out.print("Client public key file: ");
                    clientPublicKeyFile = user.readLine();
                    clientPublicKey = rsaCryptor.getPublicKey(clientPublicKeyFile);
                }

                try (BufferedReader in = new BufferedReader(new InputStreamReader(connSocket.getInputStream()));
                     PrintWriter out = new PrintWriter(new OutputStreamWriter(connSocket.getOutputStream()))
                ) {
                    while (true) {
                        String message, reply;

                        // Receive message from client
                        message = in.readLine();
                        if (message != null) {
                            // Decrypt messsage with server's private key
                            message = rsaCryptor.decryptString(serverPrivateKey, message);

                            System.out.println("Receive from client:" + message);
                            reply = message.toUpperCase();

                            if (isSecure && Objects.nonNull(clientPublicKey)) {
                                // Encrypt message with client's public key
                                reply = rsaCryptor.encryptString(clientPublicKey, reply);
                            }

                            // Send reply to client
                            out.println(reply);
                            out.flush();
                        } else {
                            System.out.println("Client has stopped sending data!");
                            break;
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
