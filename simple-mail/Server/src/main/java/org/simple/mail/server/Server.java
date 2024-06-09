package org.simple.mail.server;

import java.io.IOException;
import java.net.ServerSocket;

public class Server {
    private final static int PORT = 5000;

    public static void main(String[] args) {
        try (ServerSocket servSocket = new ServerSocket(PORT)) {
            while (true) {
                Runnable t = new ServerWorker(servSocket.accept());
                new Thread(t).start();
            }
        } catch (IOException e) {
            System.out.println("Unexpected error occurred");
            e.printStackTrace();
        }
    }

}
