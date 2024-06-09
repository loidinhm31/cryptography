package org.signature.receiver.client;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.signature.forward.util.SignatureUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

public class ReceiverClient {
    private static final String SERVER_ADDR = "127.0.0.1";
    private static final int SERVER_PORT = 5000;
    private static final String SIG_HEADER = "SIG:";
    private static final String BODY = "BODY:";

    public static void main(String[] args) {
        // TODO Auto-generated method stub
        try {
            InetAddress servAddr = InetAddress.getByName(SERVER_ADDR);
            try (Socket clientSocket = new Socket(servAddr, SERVER_PORT);
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
            ) {
                SignatureUtil verifyOperator = new SignatureUtil();

                //Enter password for generating secret key
                RSAKeyParameters senderPublicKey;
                String senderPublicKeyFile;
                System.out.print("Sender certificate file: ");
                senderPublicKeyFile = user.readLine();
                senderPublicKey = verifyOperator.getPublicKey(senderPublicKeyFile);

                String message, signature = new String(), body = new String();
                while (true) {
                    message = in.readLine();
                    if (message == null) break;

                    if (message.startsWith(SIG_HEADER) == true)
                        signature = message.substring(SIG_HEADER.length());
                    else if (message.startsWith(BODY) == true)
                        body = message.substring(BODY.length());

                    message = in.readLine();
                    if (message == null) break;

                    if (message.startsWith(SIG_HEADER) == true)
                        signature = message.substring(SIG_HEADER.length());
                    else if (message.startsWith(BODY) == true)
                        body = message.substring(BODY.length());

                    System.out.println("Receive: " + body);

                    if (verifyOperator.verifyString(senderPublicKey, body, signature))
                        System.out.println("Message is authentic");
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
