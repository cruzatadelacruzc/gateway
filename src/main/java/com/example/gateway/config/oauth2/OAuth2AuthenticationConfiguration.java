package com.example.gateway.config.oauth2;

import com.example.gateway.security.oauth2.CookieTokenExtractor;
import com.example.gateway.service.OAuth2AuthenticationService;
import com.example.gateway.web.filter.RefreshTokenFilterConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * Configures the RefreshFilter refreshing expired OAuth2 token Cookies.
 */
@Configuration
@EnableResourceServer
public class OAuth2AuthenticationConfiguration extends ResourceServerConfigurerAdapter {

    private final OAuth2AuthenticationService uaaAuthenticationService;

    private final TokenStore tokenStore;

    public OAuth2AuthenticationConfiguration(OAuth2AuthenticationService uaaAuthenticationService, TokenStore tokenStore) {
        this.uaaAuthenticationService = uaaAuthenticationService;
        this.tokenStore = tokenStore;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/auth/login").permitAll()
                .antMatchers("/auth/logout").authenticated()
               .and()
                .apply(refreshTokenSecurityConfigurerAdapter());
    }

    private RefreshTokenFilterConfigurer refreshTokenSecurityConfigurerAdapter() {
        return new RefreshTokenFilterConfigurer(uaaAuthenticationService, tokenStore);
    }

    /**
     * Configure the ResourceServer security by installing a new {@link TokenExtractor}.
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenExtractor(tokenExtractor());
    }

    /**
     * The new {@link TokenExtractor} can extract tokens from Cookies and Authorization headers.
     *
     * @return the {@link CookieTokenExtractor} bean.
     */
    @Bean
    public TokenExtractor tokenExtractor(){
        return new CookieTokenExtractor();
    }
}
