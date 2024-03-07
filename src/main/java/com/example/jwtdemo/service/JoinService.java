package com.example.jwtdemo.service;

import com.example.jwtdemo.dto.JoinDTO;
import com.example.jwtdemo.entity.UserEntity;
import com.example.jwtdemo.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {

        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDTO joinDTO) {

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();
//        String memberId = joinDTO.getMemberId();

        Boolean isExist = userRepository.existsByUsername(username);
        //Boolean isExist = userRepository.existsByMemberId(memberId);

        if (isExist) {

            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");
//        data.setMemberId(memberId);

        userRepository.save(data);
    }
}
