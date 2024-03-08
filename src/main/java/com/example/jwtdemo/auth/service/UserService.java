package com.example.jwtdemo.auth.service;

import com.example.jwtdemo.auth.dto.LoginDto;
import com.example.jwtdemo.auth.dto.UserDto;
import com.example.jwtdemo.auth.entity.UserEntity;
import com.example.jwtdemo.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;


    public UserDto socialLogin(LoginDto loginDto) {

        String socialId = loginDto.getSocialId();
        String socialProvider = loginDto.getSocialProvider();

        UserEntity user;
        UserDto userDto = new UserDto();

        if (!userRepository.existsBySocialIdAndSocialProvider(socialId, socialProvider)) {
            UserEntity userEntity = new UserEntity();
            userEntity.setSocialId(socialId);
            userEntity.setSocialProvider(socialProvider);
            userEntity.setRole("ROLE_ADMIN");

            user = userRepository.save(userEntity);
        } else {
            user = userRepository.findBySocialIdAndSocialProvider(socialId, socialProvider);
        }

        userDto.setSocialId(user.getSocialId());
        userDto.setSocialProvider(user.getSocialProvider());
        userDto.setRole(user.getRole());

        return userDto;
    }
}
