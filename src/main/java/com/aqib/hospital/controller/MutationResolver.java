package com.aqib.hospital.controller;

import com.aqib.hospital.configuration.UserService;
import com.aqib.hospital.configuration.security.BadCredentialsException;
import com.aqib.hospital.entity.DiagnosisEntity;
import com.aqib.hospital.entity.HealthEntity;
import com.aqib.hospital.entity.PersonalEntity;
import com.aqib.hospital.entity.security.AppUser;
import com.aqib.hospital.entity.security.UserRoles;
import com.aqib.hospital.model.*;
import com.aqib.hospital.repository.DiagnosisRepo;
import com.aqib.hospital.repository.HealthRepo;
import com.aqib.hospital.repository.PersonalRepo;
import com.aqib.hospital.repository.RedisRepo;
import com.aqib.hospital.repository.security.AppUserRepo;
import com.aqib.hospital.repository.security.UserRoleRepo;
import graphql.kickstart.tools.GraphQLMutationResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
@Transactional
@RequiredArgsConstructor
@Slf4j
public class MutationResolver implements GraphQLMutationResolver {

    @Autowired
    DiagnosisRepo diagnosisRepo;

    @Autowired
    HealthRepo healthRepo;

    @Autowired
    PersonalRepo personalRepo;

    @Autowired
    AppUserRepo appUserRepo;

    @Autowired
    UserRoleRepo userRoleRepo;

    @Autowired
    RedisTemplate redisTemplate;

    @Autowired
    RedisRepo redisRepo;

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final AuthenticationProvider authenticationProvider;

    @PreAuthorize("isAuthenticated()")
    public PersonalDetail createPersonalDetails(PersonalDetail personalDetail, String userName){
        PersonalEntity personalEntity = new PersonalEntity();
        HealthEntity healthEntity = new HealthEntity();
        DiagnosisEntity diagnosisEntity = new DiagnosisEntity();
        String id = appUserRepo.findByUsername(userName).getId();
        personalDetail.setId(id);
        BeanUtils.copyProperties(personalDetail,personalEntity);
        personalEntity = personalRepo.save(personalEntity);
        healthEntity.setId(personalEntity.getId());
        diagnosisEntity.setId(personalEntity.getId());
        healthRepo.save(healthEntity);
        diagnosisRepo.save(diagnosisEntity);

        return personalDetail;
    }

    @PreAuthorize("isAuthenticated()")
    public HealthDetail createHealthDetails(HealthDetail healthDetail, String phoneNumber){
        HealthEntity healthEntity = new HealthEntity();
        String id = personalRepo.findByPhoneNumber(phoneNumber).get().getId();
        BeanUtils.copyProperties(healthDetail,healthEntity);
        healthEntity.setId(id);
        healthRepo.save(healthEntity);
        healthDetail.setId(healthEntity.getId());
        return healthDetail;
    }

    @PreAuthorize("isAuthenticated()")
    public Diagnosis createDiagnosisDetails(Diagnosis diagnosis, String phoneNumber){
        DiagnosisEntity diagnosisEntity = new DiagnosisEntity();
        String id = personalRepo.findByPhoneNumber(phoneNumber).get().getId();
        BeanUtils.copyProperties(diagnosis,diagnosisEntity);
        diagnosisEntity.setId(id);
        diagnosisRepo.save(diagnosisEntity);
        diagnosis.setId(diagnosisEntity.getId());
        return diagnosis;
    }

    @PreAuthorize("isAnonymous()")
    public AppUser saveUser(AppUser appUser){
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        UserRoles userRoles = userRoleRepo.findByName("ROLE_PATIENT");
        appUser.getUserRoles().add(userRoles);
        appUser = appUserRepo.save(appUser);
        PersonalEntity personalEntity = new PersonalEntity();
        personalEntity.setId(appUser.getId());
        personalRepo.save(personalEntity);
        return appUser;
    }


    public UserRoles saveRole(UserRoles userRoles){
        userRoles = userRoleRepo.save(userRoles);
        return userRoles;
    }


    Boolean addRoleToUser(String userName, String roleName){
        AppUser appUser = appUserRepo.findByUsername(userName);
        UserRoles roles = userRoleRepo.findByName(roleName);
        appUser.getUserRoles().add(roles);
        try {
            appUserRepo.save(appUser);
            return true;
        }
        catch(Exception err) {
            return false;
        }
    }

    @PreAuthorize("isAuthenticated()")
    AppUser updateUserPassword(UpdatePassword updatePassword) {
        AppUser user = appUserRepo.findByUsername(updatePassword.getUsername());
        if(user == null)
            throw new RuntimeException("Username " + updatePassword.getUsername() +" does not exist!!");
        UsernamePasswordAuthenticationToken credentials = new UsernamePasswordAuthenticationToken(user.getUsername(), updatePassword.getCurrentPassword());
        try {
            SecurityContextHolder.getContext().setAuthentication(authenticationProvider.authenticate(credentials));
            log.info(user.getPassword());
            String password = passwordEncoder.encode(updatePassword.getCurrentPassword());
            log.info(password);
            user.setPassword(passwordEncoder.encode(updatePassword.getNewPassword()));
            user = appUserRepo.save(user);
            logoutUser();
            return user;

        } catch (Exception e) {
            throw new BadCredentialsException(user.getUsername());

        }
    }

    @PreAuthorize("isAnonymous()")
    public UserWithToken login(String username, String password ) {
        UsernamePasswordAuthenticationToken credentials = new UsernamePasswordAuthenticationToken(username, password);
        UserWithToken userWithToken = new UserWithToken();
        try {
            SecurityContextHolder.getContext().setAuthentication(authenticationProvider.authenticate(credentials));
            log.info("SECURITY_CONTEXT: " + SecurityContextHolder.getContext().getAuthentication());
            AppUser user = userService.getCurrentUser();
            userWithToken.setUser(user);
            String token = userService.getToken(user);
            if(Optional.ofNullable(redisTemplate.opsForHash().get(user.getId(),user.getId())).isPresent()){
                throw new RuntimeException("You are already logged in!");
            }
            redisTemplate.opsForHash().put(user.getId(),user.getId(),token);
            log.info(String.valueOf(redisTemplate.expire(user.getId(),25, TimeUnit.MINUTES)));
            userWithToken.setToken(token);
            return userWithToken;
        } catch (AuthenticationException ex) {
            throw new BadCredentialsException(username);
        }
    }

    @PreAuthorize("isAuthenticated()")
    public Boolean logoutUser(){

            AppUser user = userService.getCurrentUser();
//            log.info(user.toString());
            String id = user.getId();
            log.info(redisTemplate.opsForHash().get(id,id).toString());
            redisTemplate.opsForHash().delete(id,id);
            SecurityContextHolder.getContext().setAuthentication(null);
            return true;

    }
}
