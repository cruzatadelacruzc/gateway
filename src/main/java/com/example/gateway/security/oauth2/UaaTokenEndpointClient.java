package com.example.gateway.security.oauth2;

import com.example.gateway.config.AppProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;

/**
 * Client talking to UAA's token endpoint to do different OAuth2 grants.
 */
@Component
public class UaaTokenEndpointClient extends OAuth2TokenEndpointClientAdapter implements OAuth2TokenEndpointClient {


    public UaaTokenEndpointClient(@Qualifier("loadBalancedRestTemplate") RestTemplate template,
                                  AppProperties properties) {
        super(template, properties);
    }

    @Override
    void addAuthentication(HttpHeaders reqHeaders, MultiValueMap<String, String> formParams) {
        reqHeaders.add("Authorization", getAuthorization());
    }

    /**
     * @return a Basic authorization header to be used to talk to UAA.
     */
    private String getAuthorization() {
        String authorization = getClientId() + ":" + getClientSecret();
        return "Basic " + Base64Utils.encodeToString(authorization.getBytes(StandardCharsets.UTF_8));
    }
}
