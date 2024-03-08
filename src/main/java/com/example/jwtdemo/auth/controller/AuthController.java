package com.example.jwtdemo.auth.controller;


import com.example.jwtdemo.auth.dto.LoginDto;
import com.example.jwtdemo.auth.dto.UserDto;
import com.example.jwtdemo.auth.filter.JWTUtil;
import com.example.jwtdemo.auth.service.SecurityService;
import com.example.jwtdemo.auth.service.UserService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final SecurityService securityService;
    private final JWTUtil jwtUtil;

    @PostMapping("/social-login")
    public ResponseEntity<Map<String, String>> socialLogin(@RequestBody LoginDto loginDto) {
        UserDto savedOrFindUser = userService.socialLogin(loginDto);
        securityService.saveUserInSecurityContext(loginDto);
        Map<String, String> tokenMap = jwtUtil.initToken(savedOrFindUser);

        return ResponseEntity.ok(tokenMap);
    }
}
