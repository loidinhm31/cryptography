package org.signature.sender.client;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.signature.forward.util.SignatureUtil;

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
    private static final String SIG_HEADER = "SIG:";
    private static final String BODY = "BODY:";

    public static void main(String[] args) {
        try {
            InetAddress servAddr = InetAddress.getByName(SERVER_ADDR);
            try (Socket clientSocket = new Socket(servAddr, SERVER_PORT);
                 PrintWriter out = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
                 BufferedReader user = new BufferedReader(new InputStreamReader(System.in))) {
                SignatureUtil signOperator = new SignatureUtil();
                RSAKeyParameters senderPrivateKey;
                String senderPrivateKeyFile, keyPassword;

                // Enter password for extracting private key
                System.out.print("Sender private key file: ");
                senderPrivateKeyFile = user.readLine();
                System.out.print("Password for using private key: ");
                keyPassword = user.readLine();
                senderPrivateKey = signOperator.getPrivateKey(senderPrivateKeyFile, keyPassword);

                String message;

                while (true) {
                    System.out.print("Send: ");
                    message = user.readLine();
                    if (message.isEmpty())
                        break;

                    String signature = signOperator.signString(senderPrivateKey, message);
                    System.out.println("Sinature: " + signature);
                    StringBuilder builder = new StringBuilder();

                    // Encapsulate SIG header
                    builder.append(SIG_HEADER + signature);
                    builder.append("\n");
                    builder.append(BODY + message);

                    // Send message with RSA signature
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
