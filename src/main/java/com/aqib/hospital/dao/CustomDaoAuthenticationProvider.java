package com.aqib.hospital.dao;

import com.aqib.hospital.configuration.UserService;
import com.aqib.hospital.configuration.security.BadCredentialsException;
import com.aqib.hospital.entity.security.JWTUserDetails;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
public class CustomDaoAuthenticationProvider implements AuthenticationProvider {

    @Resource
    UserService userService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : (String) authentication.getPrincipal();
        if (StringUtils.isEmpty(username)) {
            throw new BadCredentialsException("invalid login details");
        }
        // get user details using Spring security user details service
        JWTUserDetails user = null;
        try {
            System.out.println(userService.loadUserByUsername(username));
            user = userService.loadUserByUsername(username);

        } catch (UsernameNotFoundException exception) {
            throw new BadCredentialsException("invalid login details");
        }
        return createSuccessfulAuthentication(authentication, user);
    }

    private Authentication createSuccessfulAuthentication(final Authentication authentication, final JWTUserDetails user) {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(user.getUsername(), authentication.getCredentials(), user.getAuthorities());
        token.setDetails(authentication.getDetails());
        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(Authentication.class);
    }
}
