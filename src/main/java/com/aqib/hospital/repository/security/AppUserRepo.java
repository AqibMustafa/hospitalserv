package com.aqib.hospital.repository.security;

import com.aqib.hospital.entity.security.AppUser;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface AppUserRepo extends MongoRepository<AppUser,String> {
    AppUser findByUsername(String username);
}
