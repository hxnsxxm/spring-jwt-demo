package com.example.jwtdemo.auth.service;

import com.example.jwtdemo.auth.dto.LoginDto;
import com.example.jwtdemo.auth.entity.UserEntity;
import com.example.jwtdemo.auth.filter.JWTUtil;
import com.example.jwtdemo.auth.jwt.CustomUserDetails;
import com.example.jwtdemo.auth.repository.UserRepository;
import java.util.Collection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import io.jsonwebtoken.Claims;

@Service
public class SecurityService {

    private final UserRepository userRepository;
    private final JWTUtil jwtUtil;

    @Autowired
    private SecurityService (UserRepository userRepository, JWTUtil jwtUtil) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    public void saveUserInSecurityContext(LoginDto loginDto) {
        String socialId = loginDto.getSocialId();
        String socialProvider = loginDto.getSocialProvider();

        saveUserInSecurityContext(socialId, socialProvider);
    }

    public void saveUserInSecurityContext(String accessToken) {
        String socialId = jwtUtil.extractClaim(accessToken,  Claims::getSubject);
        String socialProvider = jwtUtil.extractClaim(accessToken, Claims::getIssuer);
        saveUserInSecurityContext(socialId, socialProvider);
    }

    private void saveUserInSecurityContext(String socialId, String socialProvider) {
        UserDetails userDetails = loadUserBySocialIdAndSocialProvider(socialId, socialProvider);
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, authorities);

        if(authentication != null) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
        }
    }

    private UserDetails loadUserBySocialIdAndSocialProvider(String socialId, String socialProvider) {
        UserEntity user = userRepository.findBySocialIdAndSocialProvider(socialId, socialProvider);

        if(user == null) {
            //throw new TokenException(TokenErrorResult.TOKEN_EXPIRED);
            throw new RuntimeException("토큰이 만료되었습니다. loadUserBySocialIdAndSocialProvider");
        } else {
            CustomUserDetails userDetails = new CustomUserDetails(user);
            return userDetails;
        }
    }
}
