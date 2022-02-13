package com.aqib.hospital.filter;

import com.aqib.hospital.configuration.UserService;
import com.aqib.hospital.configuration.security.JWTPreAuthenticationToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final Pattern BEARER_PATTERN = Pattern.compile("^Bearer (.+?)$");
    private final UserService userService;

//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        if (request.getServletPath().equals("/login")) {
//            filterChain.doFilter(request, response);
//        } else {
//            String authHeader = request.getHeader("Authorization");
//            if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                try {
//                    String token = authHeader.split(" ")[1];
//                    Algorithm algorithm = Algorithm.HMAC256("secretkey".getBytes());
//                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
//                    DecodedJWT decodedJWT = jwtVerifier.verify(token);
//                    String username = decodedJWT.getSubject();
//                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
//                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//                    stream(roles).forEach(role -> {
//                        authorities.add(new SimpleGrantedAuthority(role));
//                    });
//                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
//                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//                    filterChain.doFilter(request, response);
//                } catch (Exception e) {
//                    response.setHeader("error", e.getMessage());
//                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
//                }
//            } else {
//                filterChain.doFilter(request, response);
//            }
//        }
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        getToken(request)
                .map(userService::loadUserByToken)
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
