package com.example.gateway.security.oauth2;

import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Extracts the access token from a cookie.
 * Falls back to a {@link BearerTokenExtractor} extracting information from the Authorization header, if no
 * cookie was found.
 */
public class CookieTokenExtractor extends BearerTokenExtractor {


    /**
     * Extract the JWT access token from the request, if present.
     * If not, then it falls back to the {@link BearerTokenExtractor} behaviour.
     *
     * @param request the request containing the cookies.
     * @return the extracted JWT token; or {@code null}.
     */
    @Override
    protected String extractToken(HttpServletRequest request) {
        String accessTokenValue;
        Cookie accessTokenCookie = OAuth2CookieHelper.getAccessTokenCookie(request);
        if (accessTokenCookie !=null){
            accessTokenValue = accessTokenCookie.getValue();
        } else {
            accessTokenValue = super.extractToken(request);
        }
        return accessTokenValue;
    }
}
