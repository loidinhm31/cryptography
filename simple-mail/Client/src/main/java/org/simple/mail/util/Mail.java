package org.simple.mail.util;

import lombok.Getter;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@Getter
public class Mail {
    public final static String FROM = "FROM: ";
    public final static String TO = "TO: ";
    public final static String DATE = "DATE: ";
    public final static String END_MAIL = ".";

    private String sender;
    private String recipient;
    private Date receivedTime;
    private String body;


    public String craftToString() {
        StringBuilder builder = new StringBuilder();
        DateFormat dateFormat = new SimpleDateFormat("yyyy-mm-dd");

        builder.append(FROM).append(sender).append("\n");
        builder.append(TO).append(recipient).append("\n");
        builder.append(DATE).append(dateFormat.format(receivedTime)).append("\n");
        builder.append(body);

        return builder.toString();
    }

    public void setTime(Date time) {
        this.receivedTime = time;

    }

    public void setSender(String sender) {
        this.sender = sender.toLowerCase();
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient.toLowerCase();
    }

    public void setBody(String body) {
        this.body = body;
    }

}
