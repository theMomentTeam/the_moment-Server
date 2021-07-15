package com.moment.the.config.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {
    @Value("${spring.jwt.secret}")
    private String SECRET_KEY;
    
    public final static long ACCESS_TOKEN_EXPIRATION_TIME = 1000L * 3600 * 6;  // milli_sec * hour * 6 = 6hour
    public final static long REFRESH_TOKEN_EXPIRATION_TIME = 1000L * 3600 * 24 * 30 * 7;  // milli_sec X hour X day X month * 7 = 7month

    enum TokenType{
        ACCESS_TOKEN("accessToken"),
        REFRESH_TOKEN("refreshToken");
        String value;

        TokenType(String value) { this.value = value; }
    }

    enum TokenClaimName{
        USER_EMAIL("userEmail"),
        TOKEN_TYPE("tokenType");
        String value;

        TokenClaimName(String value) { this.value = value; }
    }

    /**
     * JWT에 넣을 비밀키를 인코딩하여 반환한다.
     * @param secretKey 비밀키
     * @return secretKey
     */
    private Key getSigningKey(String secretKey) {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * JWT에서 claims 추출하는 함수
     * @param token JWT
     * @return Jwts - JwtToken의 Claims 값을 모두 추출한 Jwts객체
     * @throws ExpiredJwtException - JWT를 생성할 떄 지정한 유효기간을 초과할 때 발생힌다.
     * @throws IllegalArgumentException - JWT이 비어있을때 발생한다.
     * @throws MalformedJwtException - JWT가 올바르게 구성되지 않았을 떄 발생한다.
     * @throws SignatureException - JWT의 기존 서명을 확인하지 못했을 때
     * @throws UnsupportedJwtException 예상하는 형식과 일치하지 않는 특정 형식이나 구성의 JWT일 때
     * @author 정시원
     */
    public Claims extractAllClaims(String token) throws ExpiredJwtException, IllegalArgumentException, MalformedJwtException, SignatureException, UnsupportedJwtException {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(SECRET_KEY))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 토큰의 userEmail claim에서 email를 추출한다.
     * @param token JWT
     * @return String email
     * @author 정시원
     */
    public String getUserEmail(String token){
        return extractAllClaims(token).get(TokenClaimName.USER_EMAIL.value, String.class);
    }

    /**
     * 토큰의 tokenType claim에서 token type을 추출한다.
     * @param token JWT
     * @return String tokenType
     * @author 정시원
     */
    public String getTokenType(String token){
        return extractAllClaims(token).get(TokenClaimName.TOKEN_TYPE.value, String.class);
    }

    /**
     * 토큰이 만료여부에 따라 true/false를 반환한다.
     * @param token JWT
     * @return true - 토큰이 만료되었을 때
     * @author 정시원
     */
    public Boolean isTokenExpired(String token) {
        try{
            extractAllClaims(token).getExpiration();
            return false;
        }catch(ExpiredJwtException e) {
            return true;
        }
    }

    /**
     * JWT를 만든다.
     * @param userEmail JWT에 넣을 userEmail claim값
     * @param tokenType AccessToken, RefreshToken 구분
     * @param expireTime 만료시간
     * @return JWT
     * @author 정시원
     */
    private String doGenerateToken(String userEmail, TokenType tokenType, long expireTime) {
        final Claims claims = Jwts.claims();
        //AccessToken일 떄 TokenClaim에 UserEmail을 추가한다.
        if(TokenType.ACCESS_TOKEN == tokenType)
            claims.put("userEmail", userEmail);
        claims.put("tokenType", tokenType.value);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expireTime))
                .signWith(getSigningKey(SECRET_KEY), SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * AccessToken을 만든다.
     * @param email 현재 사용자의 사용자의 email
     * @return AccessToken
     * @author 정시원
     */
    public String generateAccessToken(String email) {
        return doGenerateToken(email, TokenType.ACCESS_TOKEN, ACCESS_TOKEN_EXPIRATION_TIME);
    }

    /**
     * RefreshToken을 만든다.
     * @param email 현재 사용자의 email
     * @return RefreshToken
     * @author 정시원
     */
    public String generateRefreshToken(String email) {
        return doGenerateToken(email, TokenType.REFRESH_TOKEN, REFRESH_TOKEN_EXPIRATION_TIME);
    }

}
