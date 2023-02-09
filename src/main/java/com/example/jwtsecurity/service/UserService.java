package com.example.jwtsecurity.service;

import com.example.jwtsecurity.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Value("${jwt.secret}")
    private String secretKey;
    private Long expiredMs = 1000*60*60l;  //1시간
    public String login(String username, String password){
        //인증과정 생략
        return JwtUtil.createJWT(username, secretKey,expiredMs);
    }
}
