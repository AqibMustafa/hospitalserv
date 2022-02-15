package com.aqib.hospital.filter;

import com.aqib.hospital.configuration.UserService;
import com.aqib.hospital.configuration.security.JWTPreAuthenticationToken;
import com.aqib.hospital.entity.security.JWTUserDetails;
import com.aqib.hospital.repository.RedisRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final Pattern BEARER_PATTERN = Pattern.compile("^Bearer (.+?)$");
    private final UserService userService;

    @Autowired
    RedisTemplate redisTemplate;

    @Autowired
    RedisRepo redisRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        
        Optional<JWTUserDetails> user = getToken(request).map(userService::loadUserByToken);
        if(user.isPresent()) {
            if (!Optional.ofNullable(redisTemplate.opsForHash().get(user.get().getId(),user.get().getId())).isPresent())
                throw new RuntimeException("You have been logged out or your session is expired! Please log in to proceed.");
            log.info(user.get().getId());
            log.info(redisTemplate.opsForHash().get(user.get().getId(),user.get().getId()).toString());
            List<String> userinfo = redisTemplate.opsForHash().values(user.get().getId());
            log.info(userinfo.toString());
            if(!redisTemplate.opsForHash().get(user.get().getId(),user.get().getId()).toString().equals(getToken(request).get()))
                throw new RuntimeException("You Token is expired ! Please use the correct token.");
        }
       user
                .map(userDetails -> JWTPreAuthenticationToken
                        .builder()
                        .principal(userDetails)
                        .details(new WebAuthenticationDetailsSource().buildDetails(request))
                        .build())
                .ifPresent(authentication -> SecurityContextHolder.getContext().setAuthentication(authentication));
        filterChain.doFilter(request, response);

    }

    private Optional<String> getToken(HttpServletRequest request) {
        return Optional
                .ofNullable(request.getHeader(AUTHORIZATION_HEADER))
                .filter(s -> !s.isEmpty())
                .map(BEARER_PATTERN::matcher)
                .filter(Matcher::find)
                .map(matcher -> matcher.group(1));
    }
}
