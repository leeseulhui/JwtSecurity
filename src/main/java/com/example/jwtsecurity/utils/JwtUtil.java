package com.example.jwtsecurity.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Date;

public class JwtUtil {

    public static String getUserName(String token, String secretKey){
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token)
                .getBody().get("userName", String.class);
    }
    public static boolean isExpired(String token, String secretKey){
       return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token)
               .getBody().getExpiration().before(new Date());     //data 형식

    }

    public static String createJWT(String userName, String secretKey, Long expiredMs){
        Claims claims = Jwts.claims();
        claims.put("username", userName);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiredMs))    //언제까지
                .signWith(SignatureAlgorithm.HS256, secretKey)      //무엇으로 sign 되었는지
                .compact();

    }
}
