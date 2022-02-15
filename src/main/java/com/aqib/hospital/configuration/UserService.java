package com.aqib.hospital.configuration;

import com.aqib.hospital.configuration.security.BadTokenException;
import com.aqib.hospital.entity.security.AppUser;
import com.aqib.hospital.entity.security.JWTUserDetails;
import com.aqib.hospital.entity.security.UserRoles;
import com.aqib.hospital.repository.RedisRepo;
import com.aqib.hospital.repository.security.AppUserRepo;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.function.Predicate.not;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService implements UserDetailsService {
    @Autowired
    AppUserRepo appUserRepo;

    private final JWTVerifier verifier;

    @Autowired
    Algorithm algorithm;

    @Override
    @Transactional
    public JWTUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info(username);
        AppUser appUser = appUserRepo.findByUsername(username);
        log.info(String.valueOf(appUser));
        if(appUser==null){
            throw new UsernameNotFoundException("User does not exist");
        }
        log.info(String.valueOf(getUserDetails(appUser,getToken(appUser))));
        return getUserDetails(appUser,getToken(appUser));
    }

    @Transactional
    public JWTUserDetails loadUserByToken(String token) {
        return getDecodedToken(token)
                .map(DecodedJWT::getSubject)
                .map(user -> appUserRepo.findByUsername(user))
                .map(user -> getUserDetails(user, token))
                .orElseThrow(BadTokenException::new);
    }

    @Transactional
    public AppUser getCurrentUser() {
        return Optional
                .ofNullable(SecurityContextHolder.getContext())
                .map(SecurityContext::getAuthentication)
                .map(Authentication::getName)
                .map(username -> appUserRepo.findByUsername(username))
                .orElse(null);
    }

    private Optional<DecodedJWT> getDecodedToken(String token) {
        try {
            return Optional.of(verifier.verify(token));
        } catch(JWTVerificationException ex) {
            return Optional.empty();
        }
    }

    @Transactional
    public String getToken(AppUser user) {
        Instant now = Instant.now();
        Instant expiry = Instant.now().plus(Duration.ofMinutes(25));
        return JWT
                .create()
                .withIssuer("aqib-mustafa-inc")
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiry))
                .withSubject(user.getUsername())
                .sign(algorithm);
    }

    private JWTUserDetails getUserDetails(AppUser user, String token) {
        return JWTUserDetails
                .builder()
                .id(user.getId())
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(collectionStream(user.getUserRoles().stream().map(UserRoles::getName).collect(Collectors.toList()))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList()))
                .token(token)
                .build();
    }

    public boolean isAuthenticated() {
        return Optional
                .ofNullable(SecurityContextHolder.getContext())
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .filter(not(this::isAnonymous))
                .isPresent();
    }

    private boolean isAnonymous(Authentication authentication) {
        return authentication instanceof AnonymousAuthenticationToken;
    }

    public static <T> Stream<T> collectionStream(Collection<T> collection) {
        return collection == null || collection.isEmpty() ? Stream.empty() : collection.stream();
    }

}
