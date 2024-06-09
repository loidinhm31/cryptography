package org.simple.mail.util;

import lombok.Getter;

public class Request {
    @Getter
    private String raw;
    private String command;
    @Getter
    private String parameter;

    public Request() {
    }

    public Request(String messageString) {
        this.raw = messageString;
        this.parse(raw);
    }

    public Request(String command, String parameter) {
        this.command = command;
        this.parameter = parameter;
    }

    public String craftToString() {
        StringBuilder builder = new StringBuilder();
        builder.append(this.command);
        if (this.parameter.length() > 0) {
            builder.append(IMessage.DEMILITER);
            builder.append(this.parameter);
        }

        return builder.toString();
    }

    public String getCommand() {
        return this.command.toUpperCase();
    }

    private void parse(String messageString) {
        messageString = messageString.trim();
        int firstSpace = messageString.indexOf(IMessage.DEMILITER);
        // Command has parameters
        if (firstSpace > 0) {
            command = messageString.substring(0, firstSpace);
            parameter = messageString.substring(firstSpace + 1).trim();
        }
        // Command has not parameters
        else {
            command = messageString;
            parameter = "";
        }
    }
}
