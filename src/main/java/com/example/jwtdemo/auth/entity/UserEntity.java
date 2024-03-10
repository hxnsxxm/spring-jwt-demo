package com.example.jwtdemo.auth.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Setter
@Getter
@NoArgsConstructor
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    //private String username;
    //private String password;

    private String role;
    private String socialId;
    private String socialProvider;

    private String refreshToken;

    @Builder
    public UserEntity(int id, String socialId, String socialProvider, String role, String refreshToken) {
        this.id = id;
        this.socialId = socialId;
        this.socialProvider = socialProvider;
        this.role = role;
        this.refreshToken = refreshToken;
    }
}
