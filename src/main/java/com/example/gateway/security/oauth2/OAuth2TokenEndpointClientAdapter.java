package com.example.gateway.security.oauth2;

import com.example.gateway.config.AppProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * Default base class for an {@link OAuth2TokenEndpointClient}.
 * Individual implementations for a particular OAuth2 provider can use this as a starting point.
 */
@Slf4j
public abstract class OAuth2TokenEndpointClientAdapter implements OAuth2TokenEndpointClient {

    protected final RestTemplate template;
    protected final AppProperties properties;

    public OAuth2TokenEndpointClientAdapter(RestTemplate template, AppProperties properties) {
        this.template = template;
        this.properties = properties;
    }

    /**
     * Sends a password grant to the token endpoint.
     *
     * @param username the username to authenticate.
     * @param password his password.
     * @return the access token.
     */
    @Override
    public OAuth2AccessToken sendPassword(String username, String password) {
        HttpHeaders reqHeaders = new HttpHeaders();
        reqHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.set("username", username);
        formParams.set("password", password);
        formParams.set("grant_type", "password");
        addAuthentication(reqHeaders, formParams);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formParams, reqHeaders);
        ResponseEntity<OAuth2AccessToken> response = template.postForEntity(
                getTokenEndpoint(),
                entity,
                OAuth2AccessToken.class);
        if (response.getStatusCode() != HttpStatus.OK) {
            log.debug("Failed to authenticate user with OAuth2 token endpoint, status: {}", response.getStatusCodeValue());
            throw new HttpClientErrorException(response.getStatusCode());
        }
        return response.getBody();
    }


    /**
     * Sends a refresh grant to the token endpoint using the current refresh token to obtain new tokens.
     *
     * @param refreshTokenValue the refresh token to use to obtain new tokens.
     * @return the new, refreshed access token.
     */
    @Override
    public OAuth2AccessToken sendRefreshGrant(String refreshTokenValue) {
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.add("grant_type", "refresh_token");
        formParams.add("refresh_token", refreshTokenValue);
        HttpHeaders reqHeaders = new HttpHeaders();
        addAuthentication(reqHeaders, formParams);
        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formParams, reqHeaders);
        log.debug("contacting OAuth2 token endpoint to refresh OAuth2 JWT tokens");
        ResponseEntity<OAuth2AccessToken> responseEntity = template.postForEntity(
                getTokenEndpoint(),
                entity,
                OAuth2AccessToken.class);
        if (responseEntity.getStatusCode() != HttpStatus.OK) {
            log.debug("failed to refresh tokens: {}", responseEntity.getStatusCodeValue());
            throw new HttpClientErrorException(responseEntity.getStatusCode());
        }
        log.info("refreshed OAuth2 JWT cookies using refresh_token grant");
        return responseEntity.getBody();
    }

    /**
     * Returns the configured OAuth2 token endpoint URI.
     *
     * @return the OAuth2 token endpoint URI.
     */
    private String getTokenEndpoint() {
        String accessTokenUri = properties.getSecurity().getClientAuthorization().getAccessTokenUri();
        if (accessTokenUri == null) {
            throw new InvalidClientException("no token endpoint configured in application properties");
        }
        return accessTokenUri;
    }

    abstract void addAuthentication(HttpHeaders reqHeaders, MultiValueMap<String, String> formParams);

    protected String getClientId() {
        String clientId = properties.getWebClientConfiguration().getClientId();
        if (clientId == null) {
            throw new InvalidClientException("No client-id configured in application properties");
        }
        return clientId;
    }

    protected String getClientSecret() {
        String clientSecret = properties.getWebClientConfiguration().getSecret();
        if (clientSecret == null) {
            throw new InvalidClientException("No client-secret configured in application properties");
        }
        return clientSecret;
    }
}
