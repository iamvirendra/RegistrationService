package com.analytics.registration_service.exception;

public class TokenException extends RuntimeException {
    public TokenException(String message){
        super(message);
    }
}
