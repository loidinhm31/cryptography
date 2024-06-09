package org.integrity.sender.client;

import org.bouncycastle.crypto.params.KeyParameter;
import org.integrity.forward.util.HMacUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class SenderClient {
    private static final String SERVER_ADDR = "127.0.0.1";
    private static final int SERVER_PORT = 5000;
    private static final String MIC_HEADER = "MIC:";
    private static final String BODY = "BODY:";

    public static void main(String[] args) {
        try {
            InetAddress servAddr = InetAddress.getByName(SERVER_ADDR);
            try (Socket clientSocket = new Socket(servAddr, SERVER_PORT);
                 PrintWriter out = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
                 BufferedReader user = new BufferedReader(new InputStreamReader(System.in))
            ) {

                HMacUtil hmacOperator = new HMacUtil();

                // Enter password for generating secret key
                String password;
                System.out.print("Enter password: ");
                password = user.readLine();
                KeyParameter key = hmacOperator.getSecretKey(password);

                String message;

                while (true) {
                    System.out.print("Send: ");
                    message = user.readLine();
                    if (message.isEmpty())
                        break;
                    String mic = hmacOperator.generateHMacString(key, message);
                    System.out.println("MIC: " + mic);
                    StringBuilder builder = new StringBuilder();

                    // Encapsulate MIC header
                    builder.append(MIC_HEADER + mic);
                    builder.append("\n");
                    builder.append(BODY + message);

                    // Send message with HMAC
                    out.println(builder);
                    out.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }
}
