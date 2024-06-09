package org.signature.forward.server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class ForwardServer {

    private static final int SERVER_PORT = 5000;

    public static void main(String[] args) {
        boolean isTamper = Boolean.TRUE;

        try (ServerSocket servSocket = new ServerSocket(SERVER_PORT)) {
            while (true) {
                System.out.println("Waiting connection...");

                Socket senderSocket = servSocket.accept();
                System.out.println("Sender:" + senderSocket.getInetAddress().getHostAddress());
                Socket receiverSocket = servSocket.accept();
                System.out.println("Receiver:" + receiverSocket.getInetAddress().getHostAddress());
                try (BufferedReader in = new BufferedReader(new InputStreamReader(senderSocket.getInputStream()));
                     PrintWriter out = new PrintWriter(new OutputStreamWriter(receiverSocket.getOutputStream()))
                ) {
                    while (true) {
                        String message;
                        message = in.readLine();
                        if (message != null) {

                            // Tamper data
                            if (isTamper) message = message.toUpperCase();

                            // Forward message
                            System.out.println("Forward: " + message);
                            out.println(message);
                            out.flush();
                        } else {
                            senderSocket.close();
                            receiverSocket.close();
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
