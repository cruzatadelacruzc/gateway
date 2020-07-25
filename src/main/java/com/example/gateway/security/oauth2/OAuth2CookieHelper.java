package com.example.gateway.security.oauth2;

import com.example.gateway.config.AppProperties;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.conn.util.PublicSuffixMatcher;
import org.apache.http.conn.util.PublicSuffixMatcherLoader;
import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.apache.http.conn.util.InetAddressUtils.isIPv4Address;
import static org.apache.http.conn.util.InetAddressUtils.isIPv6Address;

/**
 * Helps with OAuth2 cookie handling.
 */
@Slf4j
@Component
public class OAuth2CookieHelper {

    private final AppProperties properties;

    /**
     * Name of the session-only refresh token in case the user did not check remember me.
     */
    public static final String SESSION_TOKEN_COOKIE = "session_token";

    /**
     * The names of the Cookies we set.
     */
    private static final List<String> COOKIE_NAMES = Arrays.asList(
            OAuth2AccessToken.ACCESS_TOKEN,
            OAuth2AccessToken.REFRESH_TOKEN,
            SESSION_TOKEN_COOKIE
    );

    /**
     * Used to parse JWT claims.
     */
    private JsonParser jsonParser = JsonParserFactory.getJsonParser();

    /**
     * Public suffix matcher (to strip private subdomains off cookie scope).
     */
    PublicSuffixMatcher suffixMatcher;

    public OAuth2CookieHelper(AppProperties properties) {
        this.properties = properties;
        // Alternatively, always get an up-to-date list by passing an URL
        this.suffixMatcher = PublicSuffixMatcherLoader.getDefault();
    }

    /**
     * Returns the top level domain of the server from the request. This is used to limit the Cookie
     * to the top domain instead of the full domain name.
     * <p>
     * A lot of times, individual gateways of the same domain get their own subdomain but authentication
     * shall work across all subdomains of the top level domain.
     * <p>
     * For example, when sending a request to {@code app1.domain.com},
     * this returns {@code .domain.com}.
     *
     * @param request the HTTP request we received from the client.
     * @return the top level domain to set the cookies for.
     * Returns {@code null} if the domain is not under a public suffix (.com, .co.uk), e.g. for localhost.
     */
    private String getCookieDomain(HttpServletRequest request) {
        String domain = properties.getWebClientConfiguration().getCookieDomain();
        if (domain != null) {
            return domain;
        }
        // if not explicitly defined, use top-level domain
        domain = request.getServerName().toLowerCase();
        // strip off leading www.
        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }
        // if it isn't an IP address
        if (!isIPv4Address(domain) && !isIPv6Address(domain)) {
            // strip off private subdomains, leaving public TLD only
            String suffix = suffixMatcher.getDomainRoot(domain);
            if (suffix != null && !suffix.equals(domain)) {
                // preserve leading dot
                return "." + suffix;
            }
        }
        // no top-level domain, stick with default domain
        return null;
    }

    /**
     * Set cookie properties of access and refresh tokens.
     *
     * @param cookie   the cookie to modify.
     * @param isSecure whether it is coming from a secure request.
     * @param domain   the domain for which the cookie is valid. If {@code null}, then will fall back to default.
     */
    private void setCookieProperties(Cookie cookie, boolean isSecure, String domain) {
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(isSecure);       //if the request comes per HTTPS set the secure option on the cookie
        if (domain != null) {
            cookie.setDomain(domain);
        }
    }

    public static Cookie getAccessTokenCookie(HttpServletRequest request) {
        return getCookie(request, OAuth2AccessToken.ACCESS_TOKEN);
    }

    public static Cookie getRefreshTokenCookie(HttpServletRequest request) {
        Cookie cookie = getCookie(request, OAuth2AccessToken.REFRESH_TOKEN);
        if (cookie == null) {
            cookie = getCookie(request, SESSION_TOKEN_COOKIE);
        }
        return cookie;
    }

    /**
     * Extracts the refresh token from the refresh token cookie.
     * Since we encode additional information into the cookie, this needs to be called to get
     * hold of the enclosed JWT.
     *
     * @param refreshCookie the cookie we store the value in.
     * @return the refresh JWT from the cookie.
     */
    public static String getRefreshTokenValue(Cookie refreshCookie) {
        String value = refreshCookie.getValue();
        int i = value.indexOf('|');
        if (i > 0) {
            return value.substring(i + 1);
        }
        return value;
    }

    /**
     * Get a cookie by name from the given servlet request.
     *
     * @param request    the request containing the cookie.
     * @param cookieName the case-sensitive name of the cookie to get.
     * @return the resulting {@link Cookie}; or {@code null}, if not found.
     */
    private static Cookie getCookie(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(cookieName)) {
                    String value = cookie.getValue();
                    if (StringUtils.hasText(value)) {
                        return cookie;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Retrieve the given claim from the given token.
     *
     * @param refreshToken the JWT token to examine.
     * @param claimName    name of the claim to get.
     * @param clazz        the {@link Class} we expect to find there.
     * @return the desired claim.
     * @throws InvalidTokenException if we cannot find the claim in the token or it is of wrong type.
     */
    @SuppressWarnings("unchecked")
    private <T> T getClaim(String refreshToken, String claimName, Class<T> clazz) {
        Jwt jwt = JwtHelper.decode(refreshToken);
        String claims = jwt.getClaims();
        Map<String, Object> claimsMap = jsonParser.parseMap(claims);
        Object claimValue = claimsMap.get(claimName);
        if (claimValue == null) {
            return null;
        }
        if (!clazz.isAssignableFrom(claimValue.getClass())) {
            throw new InvalidTokenException("claim is not of expected type: " + claimName);
        }
        return (T) claimValue;
    }

    /**
     * Create a cookie out of the given refresh token.
     * Refresh token cookies contain the base64 encoded refresh token (a JWT token).
     * They also contain a hint whether the refresh token was for remember me or not.
     * If not, then the cookie will be prefixed by the timestamp it was created at followed by a pipe '|'.
     * This gives us the chance to expire session cookies regardless of the token duration.
     */
    private Cookie createRefreshTokenCookie(OAuth2RefreshToken refreshToken, boolean rememberMe) {
        int maxAge = -1;
        String name = SESSION_TOKEN_COOKIE;
        String value = refreshToken.getValue();
        if (rememberMe) {
            name = OAuth2AccessToken.REFRESH_TOKEN;
            //get expiration in seconds from the token's "exp" claim
            Integer expiration = getClaim(refreshToken.getValue(), AccessTokenConverter.EXP, Integer.class);
            if (expiration != null) {
                int now = (int) (System.currentTimeMillis() / 1000L);
                maxAge = expiration - now;
                log.debug("Refresh token valid for another {} secs", maxAge);
                //let cookie expire a bit earlier than the token to avoid race conditions
                maxAge -= 3L;
            }
        }
        Cookie refreshTokenCookie = new Cookie(name, value);
        refreshTokenCookie.setMaxAge(maxAge);
        return refreshTokenCookie;
    }

    /**
     * Create cookies using the provided values.
     *
     * @param request     the request we are handling.
     * @param accessToken the access token and enclosed refresh token for our cookies.
     * @param rememberMe  whether the user had originally checked "remember me".
     * @param result      will get the resulting cookies set.
     */
    public void createCookies(HttpServletRequest request, OAuth2AccessToken accessToken, boolean rememberMe,
                              OAuth2Cookies result) {
        String domain = getCookieDomain(request);
        Cookie accessTokenCookie = new Cookie(OAuth2AccessToken.ACCESS_TOKEN, accessToken.getValue());
        setCookieProperties(accessTokenCookie, request.isSecure(), domain);
        log.debug("Created access token cookie '{}'", accessTokenCookie.getName());

        OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
        Cookie refreshTokenCookie = createRefreshTokenCookie(refreshToken, rememberMe);
        setCookieProperties(refreshTokenCookie, request.isSecure(), domain);
        log.debug("Created refresh token cookie '{}', age: {}", refreshTokenCookie.getName(), refreshTokenCookie
                .getMaxAge());
        result.setCookies(accessTokenCookie, refreshTokenCookie);
    }

    /**
     * Checks if the refresh token session has expired.
     * Only makes sense for non-persistent cookies, i.e. when remember me was not checked.
     * The motivation for this is that we want to throw out a user after a while if he's inactive.
     * We cannot do this via refresh token validity because that one is also used for remember me.
     *
     * @param refreshCookie the refresh token cookie to check.
     * @return true, if the session is expired.
     */
    public boolean isSessionExpired(Cookie refreshCookie) {
        //no session expiration for "remember me"
        if (isRememberMe(refreshCookie)) {
            return false;
        }
        //read non-remember-me session length in secs
        int validity = properties.getWebClientConfiguration().getSessionTimeoutInSeconds();
        //no session expiration configured
        if (validity < 0) {
            return false;
        }
        Integer iat = getClaim(refreshCookie.getValue(), "iat", Integer.class);
        //token creating timestamp in secs is missing, session does not expire
        if (iat == null) {
            return false;
        }
        int now = (int) (System.currentTimeMillis() / 1000L);
        int sessionDuration = now - iat;
        log.debug("session duration {} secs, will timeout at {}", sessionDuration, validity);
        return sessionDuration > validity;            //session has expired
    }

    /**
     * Returns true if the refresh token cookie was set with remember me checked.
     * We can recognize this by the name of the cookie.
     *
     * @param refreshTokenCookie the cookie holding the refresh token.
     * @return true, if it was set persistently (i.e. for "remember me").
     */
    public static boolean isRememberMe(Cookie refreshTokenCookie) {
        return refreshTokenCookie.getName().equals(OAuth2AccessToken.REFRESH_TOKEN);
    }

    /**
     * Strip our token cookies from the array.
     *
     * @param cookies the cookies we receive as input.
     * @return the new cookie array without our tokens.
     */
    public Cookie[] stripCookies(Cookie[] cookies) {
        CookieCollection cookieCollection = new CookieCollection(cookies);
        if (cookieCollection.removeAll(COOKIE_NAMES)) {
            return cookieCollection.toArray();
        }
        return cookies;
    }

    /**
     * Clearing all cookies.
     *
     * @param request  the request containing the Cookies.
     * @param response the response used to clear them.
     */
    public void clearAll(HttpServletRequest request, HttpServletResponse response) {
        String domain = getCookieDomain(request);
        COOKIE_NAMES.forEach(cookieName -> {
            Cookie cookie = new Cookie(cookieName, "");
            setCookieProperties(cookie, request.isSecure(), domain);
            cookie.setMaxAge(0);
            response.addCookie(cookie);
            log.debug("clearing cookie {}", cookie.getName());
        });
    }
}
