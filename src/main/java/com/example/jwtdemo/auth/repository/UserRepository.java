package com.example.jwtdemo.auth.repository;

import com.example.jwtdemo.auth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Integer> {

    //Boolean existsByUsername(String username);

    //username을 받아 DB 테이블에서 회원을 조회하는 메소드 작성
    //UserEntity findByUsername(String username);


    //Boolean existsByMemberId(String memberId);
    //UserEntity findByMemberId(String memberId);

    UserEntity findBySocialIdAndSocialProvider(String socialId, String socialProvider);
    Boolean existsBySocialIdAndSocialProvider(String socialId, String socialProvider);

    UserEntity findByRefreshToken(String refreshToken);
}
