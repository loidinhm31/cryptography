package org.simple.mail.util;

import java.io.*;
import java.net.Socket;

public class TcpChannel {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    public TcpChannel(Socket s) throws IOException {
        this.socket = s;
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
    }

    public int sendResponse(Response response) {
        String message = response.craftToString();

        out.println(message);
        out.flush();
        System.out.println("Send: " + message);
        return message.length();
    }

    public Request receiveRequest() throws IOException {
        String message;

        if ((message = in.readLine()) != null) {
            System.out.println("Receive: " + message);
            return new Request(message);
        } else
            return null;
    }
}