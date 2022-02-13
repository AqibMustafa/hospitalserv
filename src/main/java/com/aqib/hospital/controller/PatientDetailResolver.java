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
import graphql.kickstart.tools.GraphQLResolver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class PatientDetailResolver implements GraphQLResolver<PatientDetail> {

    @Autowired
    PersonalRepo personalRepo;

    @Autowired
    HealthRepo healthRepo;

    @Autowired
    DiagnosisRepo diagnosisRepo;

    @Autowired
    UserService userService;

    @PreAuthorize("isAuthenticated()")
    public PersonalDetail personalDetail(PatientDetail patientDetail){
        if(!patientDetail.getPersonal()) {
            PersonalDetail personalDetail = new PersonalDetail();
            personalDetail.setId(patientDetail.getId());
            personalDetail.setFirstName("");
            personalDetail.setLastName("");
            personalDetail.setAddress("");
            personalDetail.setPhoneNumber("");
            return personalDetail;
        }
        AppUser appUser = userService.getCurrentUser();
        String id1 = appUser.getId();
        String id2 = patientDetail.getId();
        List<String> userRoles = appUser.getUserRoles().stream().map(role -> role.getName()).collect(Collectors.toList());
        if(!userRoles.stream().findAny().equals("ROLE_DOCTOR") && id1!= id2)
            throw new RuntimeException("You are not authenticated to view this");
        PersonalEntity personalEntity = personalRepo.findById(patientDetail.getId()).get();
        PersonalDetail personalDetail = new PersonalDetail();
        BeanUtils.copyProperties(personalEntity,personalDetail);
        return personalDetail;
    }

    @PreAuthorize("isAuthenticated()")
    public HealthDetail healthDetail(PatientDetail patientDetail){
        AppUser appUser = userService.getCurrentUser();
        String id1 = appUser.getId();
        String id2 = patientDetail.getId();
        List<String> userRoles = appUser.getUserRoles().stream().map(role -> role.getName()).collect(Collectors.toList());
        if(!userRoles.stream().findAny().equals("ROLE_DOCTOR") && id1!= id2)
            throw new RuntimeException("You are not authenticated to view this");
        HealthEntity healthEntity = healthRepo.findById(patientDetail.getId()).get();
        HealthDetail healthDetail = new HealthDetail();
        BeanUtils.copyProperties(healthEntity,healthDetail);
        return healthDetail;
    }

    @PreAuthorize("isAuthenticated()")
    public Diagnosis diagnosis(PatientDetail patientDetail){
        AppUser appUser = userService.getCurrentUser();
        String id1 = appUser.getId();
        String id2 = patientDetail.getId();
        List<String> userRoles = appUser.getUserRoles().stream().map(role -> role.getName()).collect(Collectors.toList());
        if(!userRoles.stream().findAny().equals("ROLE_DOCTOR") && id1!= id2)
            throw new RuntimeException("You are not authenticated to view this");
        DiagnosisEntity diagnosisEntity = diagnosisRepo.findById(patientDetail.getId()).get();
        Diagnosis diagnosis = new Diagnosis();
        BeanUtils.copyProperties(diagnosisEntity,diagnosis);
        return diagnosis;
    }
}
