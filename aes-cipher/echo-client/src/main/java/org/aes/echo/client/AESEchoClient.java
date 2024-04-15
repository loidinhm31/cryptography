package org.aes.echo.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;



public class AESEchoClient {
	private static final String SERVER_ADDR = "127.0.0.1";
	private static final int SERVER_PORT = 5000;
	
	public static void main(String[] args) {		

		try {
			InetAddress servAddr = InetAddress.getByName(SERVER_ADDR);
			try(Socket clientSocket = new Socket(servAddr, SERVER_PORT);
				BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
				PrintWriter out = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
				BufferedReader user = new BufferedReader(new InputStreamReader(System.in));
			){
/*				
				//Enter password for generating secret key
				String password;
				System.out.print("Enter password: ");
				password = user.readLine();
				AESUtil aesCryptor = new AESUtil();
				SecretKey key = aesCryptor.getSecretKey(password);
*/				
				String message, reply;

				while(true){
					System.out.print("Send to server: ");					
					message = user.readLine();
					if(message.length() == 0)
					   break;
					
					//Encrypt plain message with password-based key
					//message = aesCryptor.encryptString(key, message);
					
					//Send message to server
					out.println(message);
					out.flush();
				
					try {
						//Receive message from server
						reply = in.readLine();
						
						//Decrypt message with password-based key
						//reply = aesCryptor.decryptString(key, reply);
						
						System.out.println("Reply from Server: " + reply);
					} catch (IOException e) {
						e.printStackTrace();
					}					
				}
			}catch (Exception e){
				e.printStackTrace();
			}
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
	}

}
