package com.example.jwtdemo.auth.filter;

import com.example.jwtdemo.auth.entity.UserEntity;
import com.example.jwtdemo.auth.jwt.CustomUserDetails;
import com.example.jwtdemo.auth.service.SecurityService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final SecurityService securityService;

    public JWTFilter(JWTUtil jwtUtil, SecurityService securityService) {
        this.securityService = securityService;
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if (checkTokenValid(request)) {
            filterChain.doFilter(request, response);
        } else {
            throw new RuntimeException("알 수 없는 오류가 발생함");
        }
    }

    private boolean checkTokenValid(HttpServletRequest request) {
        String token = jwtUtil.extractTokenFromHeader(request);
        if (!jwtUtil.validateToken(token))
            securityService.saveUserInSecurityContext(token);

        return true;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String[] excludePath = {
                "/social-login",
                "/h2-console/**"
        };
        String path = request.getRequestURI();

        return Arrays.stream(excludePath).anyMatch(path::startsWith);
    }
}
