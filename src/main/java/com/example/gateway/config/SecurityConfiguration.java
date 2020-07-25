package com.example.gateway.config;

import com.example.gateway.config.oauth2.OAuth2JwtAccessTokenConverter;
import com.example.gateway.security.AuthoritiesConstants;
import com.example.gateway.security.oauth2.OAuth2SignatureVerifierClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.cloud.client.loadbalancer.RestTemplateCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfiguration extends ResourceServerConfigurerAdapter {

    private final CorsFilter corsFilter;

    private final AppProperties properties;

    public SecurityConfiguration(CorsFilter corsFilter, AppProperties properties) {
        this.corsFilter = corsFilter;
        this.properties = properties;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .csrf().ignoringAntMatchers("/h2-console/**")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
             .and()
                .addFilterBefore(corsFilter, CsrfFilter.class)
                .headers().frameOptions().disable()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
             .and()
                .authorizeRequests()
                .antMatchers("/api/**").authenticated()
                .antMatchers("/management/health").permitAll()
                .antMatchers("/management/info").permitAll()
                .antMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN);
    }

    @Bean
    public TokenStore tokenStore(JwtAccessTokenConverter jwtAccessTokenConverter) {
        return new JwtTokenStore(jwtAccessTokenConverter);
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter(OAuth2SignatureVerifierClient signatureVerifierClient) {
        return new OAuth2JwtAccessTokenConverter(properties, signatureVerifierClient);
    }

    @Bean
    @Qualifier("loadBalancedRestTemplate")
    public RestTemplate loadBalancedRestTemplate(RestTemplateCustomizer customizer) {
        RestTemplate template = new RestTemplate();
        customizer.customize(template);
        return template;
    }
}
