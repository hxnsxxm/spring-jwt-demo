package com.example.jwtdemo.auth.filter;

import com.example.jwtdemo.auth.dto.UserDto;
import com.example.jwtdemo.auth.entity.UserEntity;
import com.example.jwtdemo.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class JWTUtil {

    private UserRepository userRepository;
    private SecretKey secretKey;

    private Long ACCESS_TOKEN_EXPIRATION_PERIOD = 600000L;
    private Long REFRESH_TOKEN_EXPIRATION_PERIOD = 3600000L;

    public JWTUtil(UserRepository userRepository, @Value("${spring.jwt.secret}")String secret) {
        this.userRepository = userRepository;
        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public String getUsername(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = Jwts.parser().setSigningKey(secretKey).build().parseSignedClaims(token).getPayload();
        return claimsResolver.apply(claims);
    }

    public boolean validateToken(String accessToken) {
        if(accessToken == null || accessToken.length() <= 0) {
            throw new RuntimeException("토큰이 필요합니다");
        }

        boolean isTokenExpired = checkTokenExpired(accessToken);
        if(isTokenExpired == true) {
            throw new RuntimeException("토큰이 만료되었습니다. validateToken");
        } else {
            return isTokenExpired;
        }
    }

    public boolean checkTokenExpired(String token) {
        Date expirationDate = extractClaim(token, Claims::getExpiration);
        boolean isTokenExpired = expirationDate.before(new Date());
        return isTokenExpired;
    }

    public String createJwt(Long expirationPeriod, UserDto userDto) {
        return Jwts.builder()
                .claim("sub", userDto.getSocialId())
                .claim("iss", userDto.getSocialProvider())
                .claim("role", userDto.getRole())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationPeriod))
                .signWith(secretKey)
                .compact();
    }

    public Map<String, String> initToken(UserDto savedOrFindUser) {
        Map<String, String> tokenMap = new HashMap<>();
        String accessToken = generateAccessToken(savedOrFindUser);
        String refreshToken = generateRefreshToken(savedOrFindUser);

        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);

        updRefreshTokenInDB(refreshToken, savedOrFindUser);

        //테스트용 임시 토큰 발급
        //tokenMap.put("Bearer", generateToken(savedOrFindUser));

        return tokenMap;
    }

    //테스트용 임시 토큰 발급
    public String generateToken(UserDto userDto) {
        return createJwt(ACCESS_TOKEN_EXPIRATION_PERIOD, userDto);
    }

    public String generateAccessToken(UserDto userDto) {
        return createJwt(ACCESS_TOKEN_EXPIRATION_PERIOD, userDto);
    }

    public String generateRefreshToken(UserDto userDto) {
        return createJwt(REFRESH_TOKEN_EXPIRATION_PERIOD, userDto);
    }

    public String extractTokenFromHeader(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if(StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return header.substring(7);
        } else {
            throw new RuntimeException("토큰이 필요합니다");
        }
    }

    public boolean validateAccessToken(String accessToken) {
        if(accessToken == null || accessToken.length() <= 0) {
            throw new RuntimeException("액세스 토큰이 필요합니다.");
        }

        boolean isTokenExpired = checkTokenExpired(accessToken);
        if(isTokenExpired == true) {
            throw new RuntimeException("토큰이 만료되었습니다.");
        } else {
            return isTokenExpired;
        }
    }


    public Boolean validateRefreshToken(String refreshToken) {
        UserEntity user = userRepository.findByRefreshToken(refreshToken);

        if(user == null) {
            new RuntimeException("토큰이 만료되었습니다.");
        }

        String refreshTokenInDB = user.getRefreshToken();
        if(!refreshToken.equals(refreshTokenInDB) || checkTokenExpired(refreshTokenInDB)) {
            new RuntimeException("토큰이 만료되었습니다.");
        }

        return true;
    }

    public Map<String, String> refreshingAccessToken(UserDto userDto, String refreshToken) {
        Map<String, String> tokenMap = new HashMap<>();
        String accessToken = generateAccessToken(userDto);

        tokenMap.put("accessToken", accessToken);
        tokenMap.put("refreshToken", refreshToken);

        return tokenMap;
    }


    private void updRefreshTokenInDB(String refreshToken, UserDto savedOrFindUser) {
        savedOrFindUser.setRefreshToken(refreshToken);
        userRepository.save(savedOrFindUser.toEntity());
    }

}
