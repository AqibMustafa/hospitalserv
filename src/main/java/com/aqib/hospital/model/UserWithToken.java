package com.aqib.hospital.model;

import com.aqib.hospital.entity.security.AppUser;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserWithToken {
    String token;
    AppUser user;
}
