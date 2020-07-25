package com.example.gateway.config;

import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.web.cors.CorsConfiguration;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
/**
 * Properties specific to gateway.
 * <p>
 * Properties are configured in the {@code application.yml} file.
 */
@Getter
@ConfigurationProperties(value = "application", ignoreUnknownFields = false)
public class AppProperties {
    private final Cache cache = new Cache();
    private Security security = new Security();
    private final Gateway gateway = new Gateway();
    private final Register register = new Register();
    private final ClientApp clientApp = new ClientApp();
    private final CorsConfiguration cors = new CorsConfiguration();
    private final SignatureVerification signatureVerification = new SignatureVerification();
    private final WebClientConfiguration webClientConfiguration = new WebClientConfiguration();


    @Getter
    public static class Cache{
        private int timeToLiveSeconds = 3600;
        private int backupCount = 1;
        private final ManagementCenter managementCenter = new ManagementCenter();
        @Getter
        public static class ManagementCenter {
            private boolean enabled = false;
            private int updateInterval = 3;
            private String url ="";

            public ManagementCenter setEnabled(boolean enabled) {
                this.enabled = enabled;
                return this;
            }

            public ManagementCenter setUpdateInterval(int updateInterval) {
                this.updateInterval = updateInterval;
                return this;
            }

            public ManagementCenter setUrl(String url) {
                this.url = url;
                return this;
            }
        }
    }
    @Getter
    public static class Gateway{
        private Map<String, List<String>> authorizedMicroservicesEndpoints = new LinkedHashMap<>();
        private final RateLimiting rateLimiting = new RateLimiting();

        @Getter
        public static class RateLimiting {
            private boolean enabled = false;
            private long limit = 1000000L;
            private int durationInSeconds = 3600;

            public RateLimiting setEnabled(boolean enabled) {
                this.enabled = enabled;
                return this;
            }

            public RateLimiting setLimit(long limit) {
                this.limit = limit;
                return this;
            }

            public RateLimiting setDurationInSeconds(int durationInSeconds) {
                this.durationInSeconds = durationInSeconds;
                return this;
            }
        }
    }
    @Getter
    public static class Register{
        private String discoveryUrl = "http://admin:eureka@localhost:8761/eureka/";

        public Register setDiscoveryUrl(String discoveryUrl) {
            this.discoveryUrl = discoveryUrl;
            return this;
        }
    }
    @Getter
    public static class Security {

        private final ClientAuthorization clientAuthorization = new ClientAuthorization();

        @Data
        public static class ClientAuthorization {

            private String accessTokenUri = "http://uaa/oauth/token";

            private String tokenServiceId = "uaa";

            private String clientId = "internal";

            private String clientSecret = "internal";
        }
    }
    @Getter
    public static class ClientApp {
        private String name = "uaaApp";

        public ClientApp setName(String name) {
            this.name = name;
            return this;
        }
    }
    @Getter
    public static class SignatureVerification {
        /**
         * Maximum refresh rate for public keys in ms.
         * We won't fetch new public keys any faster than that to avoid spamming UAA in case
         * we receive a lot of "illegal" tokens.
         */
        private long publicKeyRefreshRateLimit = 10 * 1000L;
        /**
         * Maximum TTL for the public key in ms.
         * The public key will be fetched again from UAA if it gets older than that.
         * That way, we make sure that we get the newest keys always in case they are updated there.
         */
        private long ttl = 24 * 60 * 60 * 1000L;
        /**
         * Endpoint where to retrieve the public key used to verify token signatures.
         */
        private String publicKeyEndpointUri = "http://uaa/oauth/token_key";

        public SignatureVerification setPublicKeyRefreshRateLimit(long publicKeyRefreshRateLimit) {
            this.publicKeyRefreshRateLimit = publicKeyRefreshRateLimit;
            return this;
        }

        public SignatureVerification setTtl(long ttl) {
            this.ttl = ttl;
            return this;
        }

        public SignatureVerification setPublicKeyEndpointUri(String publicKeyEndpointUri) {
            this.publicKeyEndpointUri = publicKeyEndpointUri;
            return this;
        }
    }
    @Getter
    public static class WebClientConfiguration {
        private String clientId = "web_app";
        private String secret = "changeit";
        /**
         * Holds the session timeout in seconds for non-remember-me sessions.
         * After so many seconds of inactivity, the session will be terminated.
         * Only checked during token refresh, so long access token validity may
         * delay the session timeout accordingly.
         */
        private int sessionTimeoutInSeconds = 1800;
        /**
         * Defines the cookie domain. If specified, cookies will be set on this domain.
         * If not configured, then cookies will be set on the top-level domain of the
         * request you sent, i.e. if you send a request to {@code app1.your-domain.com},
         * then cookies will be set on {@code .your-domain.com}, such that they
         * are also valid for {@code app2.your-domain.com}.
         */
        private String cookieDomain;
    }
}
