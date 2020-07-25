package com.example.gateway;

import com.example.gateway.config.AppProperties;
import com.example.gateway.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@EnableConfigurationProperties(value = {AppProperties.class})
@SpringBootApplication
@EnableZuulProxy
@EnableDiscoveryClient
public class GatewayApplication implements InitializingBean {

	private static final Logger log = LoggerFactory.getLogger(GatewayApplication.class);


	private final Environment env;

	public GatewayApplication(Environment env) {
		this.env = env;
	}

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(GatewayApplication.class);
		addDefaultProfile(app);
		Environment env =  app.run(args).getEnvironment();
		logApplicationStartup(env);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Collection<String> profiles = Arrays.asList(env.getActiveProfiles());
		if (profiles.contains(Constants.PROFILE_DEV) && profiles.contains(Constants.PROFILE_PROD)) {
			log.error("You have misconfigured your application! It should not run " +
					"with both the 'dev' and 'prod' profiles at the same time.");
		}
	}

	/**
	 * Set a default to use when no profile is configured.
	 *
	 * @param app the Spring application.
	 */
	public static void addDefaultProfile(SpringApplication app) {
		Map<String, Object> defProperties = new HashMap<>();
		/*
		 * The default profile to use when no other profiles are defined
		 * This cannot be set in the application.yml file.
		 * See https://github.com/spring-projects/spring-boot/issues/1219
		 */
		defProperties.put("spring.profiles.default", Constants.PROFILE_DEV);
		app.setDefaultProperties(defProperties);
	}

	private static void logApplicationStartup(Environment env) {
		String protocol = "http";
		if (env.getProperty("server.ssl.key-store") != null) {
			protocol = "https";
		}
		String serverPort = env.getProperty("server.port");
		String contextPath = env.getProperty("server.servlet.context-path");
		if (!StringUtils.hasText(contextPath)) {
			contextPath = "/";
		}
		String hostAddress = "localhost";
		try {
			hostAddress = InetAddress.getLocalHost().getHostAddress();
		} catch (UnknownHostException e) {
			log.warn("The host name could not be determined, using `localhost` as fallback");
		}
		log.info("\n----------------------------------------------------------\n\t" +
						"Application '{}' is running! Access URLs:\n\t" +
						"Local: \t\t{}://localhost:{}{}\n\t" +
						"External: \t{}://{}:{}{}\n\t" +
						"Profile(s): \t{}\n----------------------------------------------------------",
				env.getProperty("spring.application.name"),
				protocol,
				serverPort,
				contextPath,
				protocol,
				hostAddress,
				serverPort,
				contextPath,
				env.getActiveProfiles());
	}
}
