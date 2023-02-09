package com.example.jwtsecurity.configuration;

import com.example.jwtsecurity.service.UserService;
import com.example.jwtsecurity.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
@Slf4j

public class JwtFilter extends OncePerRequestFilter {
    private final UserService userService;
    private final String secretKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Token 꺼내기
        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("authorization:{}",authorization);

        //Token 안 보내면 Block
        if(authorization == null || authorization.startsWith("Bearer "))    //authorization 이 null 이거나 Bearer 로 시작하지 않을 시
        {
            log.error("authorization 을 잘못 보냈습니다.");
            filterChain.doFilter(request,response);     //Filterchain 이 와주어야 하므로 해당 코드 작성
            return;
        }

        //Token 꺼내기(Barer 빼기)
         String  token = authorization.split("")[1];

        //Token Expired 되었는지 여부
        if(JwtUtil.isExpired(token, secretKey)){
            log.error("Token 이 만료되었습니다.");
            filterChain.doFilter(request,response);
            return;

        }

        //username Token 에서 꺼내기
        String userName = JwtUtil.getUserName(token, secretKey);
        log.info("userName : {}",userName);

        //권한 부여
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority(("USER"))));

        //Detail 을 넣어준다.
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request, response);

        }
    }
