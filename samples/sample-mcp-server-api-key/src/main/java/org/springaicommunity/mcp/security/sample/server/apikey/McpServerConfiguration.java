package org.springaicommunity.mcp.security.sample.server.apikey;

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.springaicommunity.mcp.security.server.apikey.ApiKeyEntityRepository;
import org.springaicommunity.mcp.security.server.apikey.memory.ApiKeyEntityImpl;
import org.springaicommunity.mcp.security.server.apikey.memory.InMemoryApiKeyEntityRepository;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import static org.springaicommunity.mcp.security.server.config.McpApiKeyConfigurer.mcpServerApiKey;

@Configuration
@EnableWebSecurity
class McpServerConfiguration {

	@Bean
	ToolCallbackProvider toolCallbackProvider(WeatherService weatherService) {
		return MethodToolCallbackProvider.builder().toolObjects(weatherService).build();
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
			.with(mcpServerApiKey(), (apiKey) -> apiKey.apiKeyRepository(buildApiKeyRepository()))
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			.build();
	}

	private ApiKeyEntityRepository<@NonNull ApiKeyEntityImpl> buildApiKeyRepository() {
		//@formatter:off
        var apiKey = ApiKeyEntityImpl.builder()
                .name("test api key")
                .id("api01")
                // "mycustomapikey
                .secret("mycustomapikey")
                .build();
        //@formatter:on

		return new InMemoryApiKeyEntityRepository<>(List.of(apiKey));
	}

	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOriginPatterns(List.of("http://localhost:*"));
		configuration.setAllowedMethods(List.of("*"));
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
