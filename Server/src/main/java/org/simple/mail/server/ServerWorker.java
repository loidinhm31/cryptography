package org.simple.mail.server;

import lombok.extern.slf4j.Slf4j;
import org.simple.mail.util.Request;
import org.simple.mail.util.Response;
import org.simple.mail.util.TcpChannel;

import java.io.IOException;
import java.net.Socket;
import java.util.Objects;

@Slf4j
public class ServerWorker implements Runnable {
    Socket socket;

    public ServerWorker(Socket s) {
        this.socket = s;
    }

    @Override
    public void run() {
        try {
            TcpChannel channel = new TcpChannel(socket);
            RequestProcessor processor = new RequestProcessor();
            while (true) {
                Request request;
                if (Objects.isNull(request = channel.receiveRequest()))
                    break;
                processor.setRequest(request);
                if (processor.process() < 0)
                    break;
                Response response = processor.getResponse();
                if (Objects.nonNull(response))
                    channel.sendResponse(processor.getResponse());
            }
            socket.close();

        } catch (IOException e) {
            log.error("Unexpected error occurred", e);
        }
    }

}
