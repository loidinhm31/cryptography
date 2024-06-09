package org.integrity.receiver.client;

import org.bouncycastle.crypto.params.KeyParameter;
import org.integrity.forward.util.HMacUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class ReceiverClient {
    private static final String SERVER_ADDR = "10.0.2.9";
    private static final int SERVER_PORT = 5000;
    private static final String MIC_HEADER = "MIC:";
    private static final String BODY = "BODY:";

    public static void main(String[] args) {
        try {
            InetAddress servAddr = InetAddress.getByName(SERVER_ADDR);
            try (Socket clientSocket = new Socket(servAddr, SERVER_PORT);
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 BufferedReader user = new BufferedReader(new InputStreamReader(System.in))) {
                HMacUtil hmacOperator = new HMacUtil();

                // Enter password for generating secret key
                String password;
                System.out.print("Enter password: ");
                password = user.readLine();
                KeyParameter key = hmacOperator.getSecretKey(password);

                String message, mic = new String(), body = new String();
                while (true) {
                    message = in.readLine();
                    if (message == null) break;

                    if (message.startsWith(MIC_HEADER))
                        mic = message.substring(MIC_HEADER.length());
                    else if (message.startsWith(BODY))
                        body = message.substring(BODY.length());

                    message = in.readLine();
                    if (message == null) break;

                    if (message.startsWith(MIC_HEADER))
                        mic = message.substring(MIC_HEADER.length());
                    else if (message.startsWith(BODY))
                        body = message.substring(BODY.length());

                    System.out.println("Receive: " + body);

                    if (hmacOperator.verifyHMacString(key, body, mic))
                        System.out.println("Message is integrity");
                    else
                        System.out.println("Message is not authentic");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }
}
