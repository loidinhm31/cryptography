package org.simple.mail.error;

public class DecryptPrivateKeyInfoException extends Exception {
    private String message;


    public DecryptPrivateKeyInfoException(String message) {
        this.message = message;
    }

    @Override
    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
