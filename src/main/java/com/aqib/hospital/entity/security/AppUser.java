package com.aqib.hospital.entity.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import java.util.ArrayList;
import java.util.Collection;


@Data
@AllArgsConstructor
@NoArgsConstructor
@Document("user_detail")
public class AppUser {
    @Id
    String id;
    String name;
    String username;
    String password;
    @DBRef
    Collection<UserRoles> userRoles = new ArrayList<>();
}
