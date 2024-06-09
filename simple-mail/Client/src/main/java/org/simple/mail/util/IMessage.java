package org.simple.mail.util;

public interface IMessage {
    char DEMILITER = ' ';

    String craftToString();

    void parse(String str);
}
