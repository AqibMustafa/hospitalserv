package com.aqib.hospital.configuration.security;

import lombok.RequiredArgsConstructor;

import java.text.MessageFormat;

@RequiredArgsConstructor
public class BadCredentialsException extends RuntimeException{
    private static final long serialVersionUID = 4129146858129498534L;
    private final String username;

    @Override
    public String getMessage() {
        return MessageFormat.format("username or password didn''t match for ''{0}''", username);
    }
}
