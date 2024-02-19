package com.huyvu.springsecurityjwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Date;

@Slf4j
public class SecurityUtils {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String AUTHORIZATION_PREFIX = "Bearer_";
    private static final int SIX_HOUR = 1000 * 60 * 60 * 6;

    private static final String USER_CLAIM = "user";
    private static final String ISSUER = "auth0";

    @Value("${jwt-key}")
    private static String SECRET_KEY = "iloveu3000";

    private static final Algorithm ALGORITHM = Algorithm.HMAC256(SECRET_KEY);


    @SneakyThrows
    public static JwtTokenVo validateJWTToken(String token) {
        var verifier = JWT.require(ALGORITHM)
                .withIssuer(ISSUER)
                .build();
        var decodedJWT = verifier.verify(token);
        var expAt = decodedJWT.getExpiresAt();
        Assert.isTrue(isTokenNotExpired(expAt), "Token is expired.");
        var userClaim = decodedJWT.getClaims().get(USER_CLAIM).asString();

        var jwtTokenVo = OBJECT_MAPPER.readValue(userClaim, JwtTokenVo.class);

        return jwtTokenVo;

    }


    private static boolean isTokenNotExpired(Date expAt) {
        return expAt.after(new Date());
    }

    @SneakyThrows
    public static String createToken(JwtTokenVo jwtTokenVo) {
        var builder = JWT.create();
        var tokenJson = OBJECT_MAPPER.writeValueAsString(jwtTokenVo);
        builder.withClaim(USER_CLAIM, tokenJson);
        return builder
                .withIssuedAt(new Date())
                .withIssuer(ISSUER)
                .withExpiresAt(new Date(System.currentTimeMillis() + SIX_HOUR))
                .sign(ALGORITHM);
    }

    public static String getTokenFromRequest(HttpServletRequest req) {
        var cookies = req.getCookies();
        var authCookie = Arrays.stream(cookies)
                .filter(e -> e.getName().equals(AUTHORIZATION_HEADER))
                .findFirst()
                .orElseThrow();
        String authorizationHeader = authCookie.getValue();
        Assert.isTrue(authorizationHeader.startsWith(AUTHORIZATION_PREFIX), "Authorization header must start with '" + AUTHORIZATION_PREFIX + "'.");

        String jwtToken = authorizationHeader.substring(AUTHORIZATION_PREFIX.length());
        return jwtToken;
    }

    public static void setTokenToResponse(HttpServletResponse res, String token) {
        var cookie = new Cookie(AUTHORIZATION_HEADER, AUTHORIZATION_PREFIX + token);
        cookie.setMaxAge(3600 * 6);
        cookie.setPath("/");
        res.addCookie(cookie);
    }
}