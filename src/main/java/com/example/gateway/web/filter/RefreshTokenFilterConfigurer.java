package com.example.gateway.web.filter;

import com.example.gateway.service.OAuth2AuthenticationService;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.DefaultSecurityFilterChain;

/**
 * Configures a {@link RefreshTokenFilter} to refresh access tokens if they are about to expire.
 *
 * @see RefreshTokenFilter
 */
public class RefreshTokenFilterConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    /**
     * {@link RefreshTokenFilter} needs the {@link OAuth2AuthenticationService} to refresh cookies using the refresh token.
     */
    private OAuth2AuthenticationService authenticationService;
    private final TokenStore tokenStore;

    public RefreshTokenFilterConfigurer(OAuth2AuthenticationService uaaAuthenticationService, TokenStore tokenStore) {
        this.authenticationService = uaaAuthenticationService;
        this.tokenStore = tokenStore;
    }

    /**
     * Install {@link RefreshTokenFilter} as a servlet Filter.
     */
    @Override
    public void configure(HttpSecurity builder) throws Exception {
        RefreshTokenFilter filter = new RefreshTokenFilter(authenticationService, tokenStore);
        builder.addFilterBefore(filter, OAuth2AuthenticationProcessingFilter.class);
    }
}
