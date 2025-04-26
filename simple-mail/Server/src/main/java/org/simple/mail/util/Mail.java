package org.simple.mail.util;

import lombok.Getter;
import lombok.Setter;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

@Getter
public class Mail {
    public final static String FROM = "FROM: ";
    public final static String TO = "TO: ";
    public final static String DATE = "DATE: ";
    public final static String END_MAIL = ".";

    @Setter
    private int id;
    private String sender;
    private String recipient;
    private Date receivedTime;
    @Setter
    private String body;


    public String craftToString() {
        StringBuilder builder = new StringBuilder();
        DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");

        builder.append(FROM + sender + "\n");
        builder.append(TO + recipient + "\n");
        builder.append(DATE + dateFormat.format(receivedTime) + "\n");
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
}
