package org.aes.echo.server;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;

public class AESEchoServer {
    private static final int SERVER_PORT = 5000;

    public static void main(String[] args) {

        try (ServerSocket servSocket = new ServerSocket(SERVER_PORT);
             BufferedReader user = new BufferedReader(new InputStreamReader(System.in))
        ) {
            while (true) {
                System.out.println("Waiting connection...");

                //Accept client connection
                Socket connSocket = servSocket.accept();
                System.out.println("Client: " + connSocket.getInetAddress().getHostAddress());

                try (BufferedReader in = new BufferedReader(new InputStreamReader(connSocket.getInputStream()));
                     PrintWriter out = new PrintWriter(new OutputStreamWriter(connSocket.getOutputStream()))
                ) {
/*					
					//Enter password for generating secret key
					String password;
					System.out.print("Enter password: ");
					password = user.readLine();
					AESUtil aesCryptor = new AESUtil();
					SecretKey key = aesCryptor.getSecretKey(password);
*/
                    while (true) {
                        String message, reply;

                        //Receive message from client
                        message = in.readLine();

                        if (message != null) {
                            //Decrypt message with password-based key
                            //message = aesCryptor.decryptString(key, message);

                            System.out.println("Receive from client: " + message);
                            reply = message.toUpperCase();

                            //Encrypt message with password-based key
                            //reply = aesCryptor.encryptString(key, reply);

                            //Send reply to client
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

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
