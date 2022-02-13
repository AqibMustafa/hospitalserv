package com.aqib.hospital;

import com.aqib.hospital.repository.security.AppUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
@EnableAspectJAutoProxy
public class HospitalApplication {
	@Autowired
	AppUserRepo appUserRepo;
	public static void main(String[] args) {
		SpringApplication.run(HospitalApplication.class, args);
	}

}
