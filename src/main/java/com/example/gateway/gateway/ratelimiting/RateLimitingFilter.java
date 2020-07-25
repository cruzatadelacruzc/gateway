package com.example.gateway.gateway.ratelimiting;

import com.example.gateway.config.AppProperties;
import com.example.gateway.security.SecurityUtils;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.grid.GridBucketState;
import io.github.bucket4j.grid.ProxyManager;
import io.github.bucket4j.grid.jcache.JCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;

import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.CompleteConfiguration;
import javax.cache.configuration.MutableConfiguration;
import javax.cache.spi.CachingProvider;
import java.time.Duration;
import java.util.function.Supplier;

/**
 * Zuul filter for limiting the number of HTTP calls per client.
 */
@Slf4j
public class RateLimitingFilter extends ZuulFilter {

    private final AppProperties properties;

    private ProxyManager<String> buckets;

    public final static String GATEWAY_RATE_LIMITING_CACHE_NAME = "gateway-rate-limiting";

    // cache for storing token buckets, where IP is key.
    private Cache<String, GridBucketState> cache;


    public RateLimitingFilter(AppProperties properties) {
        this.properties = properties;
        CachingProvider provider = Caching.getCachingProvider();
        CacheManager manager = provider.getCacheManager();
        CompleteConfiguration<String, GridBucketState> config = new MutableConfiguration<String, GridBucketState>()
                .setTypes(String.class, GridBucketState.class);
        this.cache = manager.createCache(GATEWAY_RATE_LIMITING_CACHE_NAME, config);
        this.buckets = Bucket4j.extension(JCache.class).proxyManagerForCache(this.cache);
    }

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 10;
    }

    @Override
    public boolean shouldFilter() {
        // specific APIs can be filtered out using
        // if (RequestContext.getCurrentContext().getRequest().getRequestURI().startsWith("/api")) { ... }
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        // The ID that will identify the limit: the user login or the user IP address.
        String bucketId = SecurityUtils
                .getCurrentUserLogin()
                .orElse(RequestContext.getCurrentContext().getRequest().getRemoteAddr());

        Bucket bucket = this.buckets.getProxy(bucketId, getConfigSupplier());

        // tryConsume returns false immediately if no tokens available with the bucket
        if (bucket.tryConsume(1)) {
            // the limit is not exceeded
            log.debug("API rate limit OK for {}", bucketId);
        } else {
            // limit is exceeded
            log.info("API rate limit exceeded for {}", bucketId);
            // Create a Zuul response error when the API limit is exceeded.
            RequestContext requestContext = RequestContext.getCurrentContext();
            requestContext.setResponseStatusCode(HttpStatus.TOO_MANY_REQUESTS.value());
            if (requestContext.getResponseBody() == null) {
                requestContext.setResponseBody("API rate limit exceeded");
                requestContext.setSendZuulResponse(false);
            }
        }
        return null;
    }

    private Supplier<BucketConfiguration> getConfigSupplier() {
        return () -> Bucket4j.configurationBuilder()
                .addLimit(Bandwidth.simple(properties.getGateway().getRateLimiting().getLimit(),
                        Duration.ofSeconds(properties.getGateway().getRateLimiting().getDurationInSeconds())))
                .build();
    }
}
