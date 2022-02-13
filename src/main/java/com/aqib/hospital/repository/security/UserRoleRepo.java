package com.aqib.hospital.repository.security;

import com.aqib.hospital.entity.security.UserRoles;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UserRoleRepo extends MongoRepository<UserRoles,String> {
    UserRoles findByName(String name);
}
