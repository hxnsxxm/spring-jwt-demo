package com.example.jwtdemo.auth.dto;

import lombok.Data;

@Data
public class UserDto {
    private String socialId;
    private String socialProvider;
    private String role;
}
