package com.example.gateway.service;

import com.example.gateway.security.oauth2.*;
import com.example.gateway.web.rest.vm.LoginVM;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Manages authentication cases for OAuth2 updating the cookies holding access and refresh tokens accordingly.
 * <p>
 * It can authenticate users, refresh the token cookies should they expire and log users out.
 */
@Slf4j
@Service
public class OAuth2AuthenticationService {

    /**
     * Used to contact the OAuth2 token endpoint.
     */
    private final OAuth2TokenEndpointClient authorizationClient;

    /**
     * Helps us with cookie handling.
     */
    private final OAuth2CookieHelper cookieHelper;

    /**
     * Number of milliseconds to cache refresh token grants so we don't have to repeat them in case of parallel requests.
     */
    private static final long REFRESH_TOKEN_VALIDITY_MILLIS = 10000L;

    /**
     * Caches Refresh grant results for a refresh token value so we can reuse them.
     * This avoids hammering UAA in case of several multi-threaded requests arriving in parallel.
     */
    private final PersistentTokenCache<OAuth2Cookies> recentlyRefreshed;

    public OAuth2AuthenticationService(OAuth2TokenEndpointClient authorizationClient,
                                       OAuth2CookieHelper cookieHelper) {
        this.authorizationClient = authorizationClient;
        this.cookieHelper = cookieHelper;
        this.recentlyRefreshed = new PersistentTokenCache<>(REFRESH_TOKEN_VALIDITY_MILLIS);
    }

    /**
     * Authenticate the user by username and password.
     *
     * @param request  the request coming from the client.
     * @param response the response going back to the server.
     * @param loginMV  the params holding the username, password and rememberMe.
     * @return the {@link OAuth2AccessToken} as a {@link ResponseEntity}. Will return {@code OK (200)}, if successful.
     * If the UAA cannot authenticate the user, the status code returned by UAA will be returned.
     */
    public OAuth2AccessToken authenticate(LoginVM loginMV, HttpServletRequest request, HttpServletResponse response) {
        try {
            OAuth2AccessToken accessToken = authorizationClient.sendPassword(
                    loginMV.getUsername(), loginMV.getPassword()
            );
            OAuth2Cookies cookies = new OAuth2Cookies();
            cookieHelper.createCookies(request, accessToken, loginMV.getRememberMe(), cookies);
            cookies.addCookiesTo(response);
            log.debug("Successfully authenticated user {}", loginMV.getUsername());
            return accessToken;
        } catch (HttpClientErrorException ex) {
            log.error("Failed to get OAuth2 tokens from UAA", ex);
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    /**
     * Try to refresh the access token using the refresh token provided as cookie.
     * Note that browsers typically send multiple requests in parallel which means the access token
     * will be expired on multiple threads. We don't want to send multiple requests to UAA though,
     * so we need to cache results for a certain duration and synchronize threads to avoid sending
     * multiple requests in parallel.
     *
     * @param request       the request potentially holding the refresh token.
     * @param response      the response setting the new cookies (if refresh was successful).
     * @param refreshCookie the refresh token cookie. Must not be null.
     * @return the new servlet request containing the updated cookies for relaying downstream.
     */
    public HttpServletRequest refreshToken(HttpServletRequest request, HttpServletResponse response, Cookie
            refreshCookie) {
        //check if non-remember-me session has expired
        if (cookieHelper.isSessionExpired(refreshCookie)) {
            log.info("Session has expired due to inactivity");
            //logout(request, response);       //logout to clear cookies in browser
            return stripTokens(request);            //don't include cookies downstream
        }
        OAuth2Cookies cookies = getCachedCookies(refreshCookie.getValue());
        synchronized (cookies) {
            //check if we have a result from another thread already
            if (cookies.getAccessTokenCookie() == null) { //no, we are first!
                //send a refresh_token grant to UAA, getting new tokens
                String refreshCookieValue = OAuth2CookieHelper.getRefreshTokenValue(refreshCookie);
                OAuth2AccessToken accessToken = authorizationClient.sendRefreshGrant(refreshCookieValue);
                boolean rememberMe = OAuth2CookieHelper.isRememberMe(refreshCookie);
                cookieHelper.createCookies(request, accessToken, rememberMe, cookies);
                //add cookies to response to update browser
                cookies.addCookiesTo(response);
            } else {
                log.debug("Reusing cached refresh_token grant");
            }
            //replace cookies in original request with new ones
            CookieCollection requestCookies = new CookieCollection(request.getCookies());
            requestCookies.add(cookies.getAccessTokenCookie());
            requestCookies.add(cookies.getRefreshTokenCookie());
            return new CookiesHttpServletRequestWrapper(request, requestCookies.toArray());
        }
    }

    /**
     * Strips token cookies preventing them from being used further down the chain.
     * For example, the OAuth2 client won't checked them and they won't be relayed to other services.
     *
     * @param httpServletRequest the incoming request.
     * @return the request to replace it with which has the tokens stripped.
     */
    public HttpServletRequest stripTokens(HttpServletRequest httpServletRequest) {
        Cookie[] cookies = cookieHelper.stripCookies(httpServletRequest.getCookies());
        return new CookiesHttpServletRequestWrapper(httpServletRequest, cookies);
    }

    /**
     * Get the result from the cache in a thread-safe manner.
     *
     * @param refreshTokenValue the refresh token for which we want the results.
     * @return a RefreshGrantResult for that token. This will either be empty, if we are the first one to do the
     * request, or contain some results already, if another thread already handled the grant for us.
     */
    private OAuth2Cookies getCachedCookies(String refreshTokenValue) {
        synchronized (recentlyRefreshed) {
            OAuth2Cookies ctx = recentlyRefreshed.get(refreshTokenValue);
            if (ctx == null) {
                ctx = new OAuth2Cookies();
                recentlyRefreshed.put(refreshTokenValue, ctx);
            }
            return ctx;
        }
    }


    /**
     * Logs the user out by clearing all cookies.
     *
     * @param request  the request containing the Cookies.
     * @param response the response used to clear them.
     */
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        cookieHelper.clearAll(request, response);
    }
}
