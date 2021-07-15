package com.moment.the.config.security.jwt;

import com.moment.the.config.security.auth.MyUserDetailsService;
import com.moment.the.exceptionAdvice.exception.InvalidTokenException;
import com.moment.the.exceptionAdvice.exception.UserNotFoundException;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {
    private final MyUserDetailsService myUserDetailsService;
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = req.getHeader("Authorization");
        String refreshToken = req.getHeader("RefreshToken");

        String userEmail;

        // Access Token이 null이면 검증할 필요가 없다.
        if (accessToken != null) {
            log.debug("=== accessToken 검증 시작 ===");

            userEmail = accessTokenExtractEmail(accessToken);
            if(userEmail != null)
                registerUserInfoInSecurityContext(userEmail, req);

            // Access Token이 만료되고 Refresh Token이 존재해야지 새로운 AccessToken을 반한한다.
            if(jwtUtil.isTokenExpired(accessToken) && refreshToken != null){
                log.debug("=== AccessToken 만료 ===");

                String newAccessToken = generateNewAccessToken(refreshToken);
                res.addHeader("JwtToken", newAccessToken);

                log.debug("=== AccessToken 발급 ===");
            }
        }
        filterChain.doFilter(req, res);
    }

    /**
     * accessToken에서 userEmail claim 값을 추출한다.
     *
     * @param accessToken Access Token
     * @return userEmail - accessToken에서 정상적으로 email를 추출할때 user email을 반한한다.
     * @throws InvalidTokenException - accessToken이 null이 아니고 올바르지 않을때 발생한다.
     * @author 정시원
     */
    private String accessTokenExtractEmail(String accessToken) {
        try {
            if(jwtUtil.getTokenType(accessToken).equals(JwtUtil.TokenType.REFRESH_TOKEN.value))
                return accessToken;
            else
                return null;
        } catch (IllegalArgumentException | ExpiredJwtException e) {
            return null;
        } catch (MalformedJwtException | UnsupportedJwtException | SignatureException e ) {
            throw new InvalidTokenException();
        }
    }

    /**
     * user email로 사용자의 유무를 판단해 SecurityContext에 유저를 등록한다.
     *
     * @param userEmail - String
     * @param req       - HttpServletRequest
     * @throws UserNotFoundException - 해당 사용자가 없을 경우 throw 된다.
     * @author 정시원
     */
    private void registerUserInfoInSecurityContext(String userEmail, HttpServletRequest req) {
        try {
            UserDetails userDetails = myUserDetailsService.loadUserByUsername(userEmail);

            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        } catch (NullPointerException e) {
            throw new UserNotFoundException();
        }
    }

    /**
     * @param refreshToken - 유저가 가지고 있는 refreshToken
     * @return newAccessToken - 새로만든 AccessToken을 발급합니다.
     * @throws InvalidTokenException RefreshToken이 올바르지 않을때 throws된다.
     * @author 정시원
     */
    private String generateNewAccessToken(String refreshToken) {
        try {
            return jwtUtil.generateAccessToken(jwtUtil.getUserEmail(refreshToken));
        } catch (IllegalArgumentException | UnsupportedJwtException | SignatureException | MalformedJwtException | ExpiredJwtException e) {
            throw new InvalidTokenException();
        }
    }
}
