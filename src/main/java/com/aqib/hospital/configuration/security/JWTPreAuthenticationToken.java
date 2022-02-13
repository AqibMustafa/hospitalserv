package com.aqib.hospital.configuration.security;

import com.aqib.hospital.entity.security.JWTUserDetails;
import lombok.Builder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class JWTPreAuthenticationToken extends PreAuthenticatedAuthenticationToken {
    private static final long serialVersionUID = -5304730621727936850L;

    @Builder
    public JWTPreAuthenticationToken(JWTUserDetails principal, WebAuthenticationDetails details) {
        super(principal, null, principal.getAuthorities());
        super.setDetails(details);
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
