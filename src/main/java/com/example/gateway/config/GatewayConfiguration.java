package com.example.gateway.config;

import com.example.gateway.gateway.accesscontrol.AccessControlFilter;
import com.example.gateway.gateway.ratelimiting.RateLimitingFilter;
import lombok.AllArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.netflix.zuul.filters.RouteLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@AllArgsConstructor
public class GatewayConfiguration {

    private final AppProperties properties;

    @Bean
    public AccessControlFilter accessControlFilter(RouteLocator routeLocator) {
        return new AccessControlFilter(routeLocator, properties);
    }


    /**
     * Configures the Zuul filter that limits the number of API calls per user.
     * <p>
     * This uses Bucket4J to limit the API calls, see {@link RateLimitingFilter}.
     */
    @Bean
    @ConditionalOnProperty("application.gateway.rate-limiting.enabled")
    public RateLimitingFilter rateLimitingFilter() {
        return new RateLimitingFilter(properties);
    }
}
