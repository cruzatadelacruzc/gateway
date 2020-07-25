package com.example.gateway.security.oauth2;

import lombok.Getter;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;


/**
 * Holds the access token and refresh token cookies.
 */
@Getter
public class OAuth2Cookies {
    private Cookie accessTokenCookie;
    private Cookie refreshTokenCookie;

    void setCookies(Cookie accessTokenCookie, Cookie refreshTokenCookie) {
        this.accessTokenCookie = accessTokenCookie;
        this.refreshTokenCookie = refreshTokenCookie;
    }

    /**
     * Add the access token and refresh token as cookies to the response after successful authentication.
     *
     * @param response the response to add them to.
     */
    public void addCookiesTo(HttpServletResponse response) {
        response.addCookie(this.accessTokenCookie);
        response.addCookie(this.refreshTokenCookie);
    }
}
