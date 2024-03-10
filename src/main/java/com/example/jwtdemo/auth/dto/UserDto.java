package com.example.jwtdemo.auth.dto;

import com.example.jwtdemo.auth.entity.UserEntity;
import lombok.Builder;
import lombok.Data;

@Data
public class UserDto {
    private int id;
    private String socialId;
    private String socialProvider;
    private String role;
    private String refreshToken;

    public UserEntity toEntity() {
        return UserEntity.builder()
                .id(id)
                .socialId(socialId)
                .socialProvider(socialProvider)
                .role(role)
                .refreshToken(refreshToken)
                .build();
    }
}
