package com.aqib.hospital.entity.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ConfirmationToken {
    @Id
    String id;
    String token;
    LocalDateTime createdAt;
    LocalDateTime expiredAt;
}
