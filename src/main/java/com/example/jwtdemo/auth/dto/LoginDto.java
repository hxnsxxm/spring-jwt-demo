package com.example.jwtdemo.auth.dto;

import lombok.Data;

@Data
public class LoginDto {
    private String socialId;
    private String socialProvider;
}
