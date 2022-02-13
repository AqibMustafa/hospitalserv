package com.aqib.hospital.controller;

import com.aqib.hospital.configuration.UserService;
import com.aqib.hospital.entity.DiagnosisEntity;
import com.aqib.hospital.entity.HealthEntity;
import com.aqib.hospital.entity.PersonalEntity;
import com.aqib.hospital.entity.security.AppUser;
import com.aqib.hospital.model.Diagnosis;
import com.aqib.hospital.model.HealthDetail;
import com.aqib.hospital.model.PatientDetail;
import com.aqib.hospital.model.PersonalDetail;
import com.aqib.hospital.repository.DiagnosisRepo;
import com.aqib.hospital.repository.HealthRepo;
import com.aqib.hospital.repository.PersonalRepo;
import com.aqib.hospital.repository.security.AppUserRepo;
import graphql.kickstart.tools.GraphQLQueryResolver;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Component
@Transactional
public class QueryResolver implements GraphQLQueryResolver {

    @Autowired
    DiagnosisRepo diagnosisRepo;

    @Autowired
    HealthRepo healthRepo;

    @Autowired
    PersonalRepo personalRepo;

    @Autowired
    AppUserRepo appUserRepo;

    @Autowired
    UserService userService;

    public PatientDetail patientDetail(String id, Boolean personal){
        PatientDetail patientDetail = new PatientDetail();
        patientDetail.setId(id);
        patientDetail.setPersonal(personal);
        return patientDetail;
    }

    @PreAuthorize("isAuthenticated()")
    public PersonalDetail getPersonalDetail(String id){
        AppUser appUser = userService.getCurrentUser();
        String id1 = appUser.getId();
        List<String> userRoles = appUser.getUserRoles().stream().map(role -> role.getName()).collect(Collectors.toList());
        if(!userRoles.stream().findAny().equals("ROLE_DOCTOR") && id1!= id)
            throw new RuntimeException("You are not authenticated to view this");
        PersonalEntity personalEntity = personalRepo.findById(id).get();
        PersonalDetail personalDetail = new PersonalDetail();
        BeanUtils.copyProperties(personalEntity,personalDetail);
        return personalDetail;
    }

    @PreAuthorize("isAuthenticated()")
    public HealthDetail getHealthDetail(String id){
        AppUser appUser = userService.getCurrentUser();
        String id1 = appUser.getId();
        List<String> userRoles = appUser.getUserRoles().stream().map(role -> role.getName()).collect(Collectors.toList());
        if(!userRoles.stream().findAny().equals("ROLE_DOCTOR") && id1!= id)
            throw new RuntimeException("You are not authenticated to view this");
        HealthEntity healthEntity = healthRepo.findById(id).get();
        HealthDetail healthDetail = new HealthDetail();
        BeanUtils.copyProperties(healthEntity,healthDetail);
        return healthDetail;
    }

    @PreAuthorize("isAuthenticated()")
    public Diagnosis getDiagnosisDetail(String id){
        AppUser appUser = userService.getCurrentUser();
        String id1 = appUser.getId();
        List<String> userRoles = appUser.getUserRoles().stream().map(role -> role.getName()).collect(Collectors.toList());
        if(!userRoles.stream().findAny().equals("ROLE_DOCTOR") && id1!= id)
            throw new RuntimeException("You are not authenticated to view this");
        DiagnosisEntity diagnosisEntity = diagnosisRepo.findById(id).get();
        Diagnosis diagnosis = new Diagnosis();
        BeanUtils.copyProperties(diagnosisEntity,diagnosis);
        return diagnosis;
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public AppUser getUser(String userName){
        return appUserRepo.findByUsername(userName);
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<AppUser> getUsers(){
        return appUserRepo.findAll();
    }

}
