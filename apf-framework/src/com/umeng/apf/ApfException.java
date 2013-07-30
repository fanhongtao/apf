package com.umeng.apf;

public class ApfException extends Exception {
    private static final long serialVersionUID = -6633747561600265183L;

    public ApfException() {
    }

    public ApfException(String detailMessage) {
        super(detailMessage);
    }

    public ApfException(String detailMessage, Throwable throwable) {
        super(detailMessage, throwable);
    }

    public ApfException(Throwable throwable) {
        super(throwable);
    }
}