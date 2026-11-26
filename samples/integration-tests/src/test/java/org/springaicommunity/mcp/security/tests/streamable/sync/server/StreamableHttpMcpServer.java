package org.springaicommunity.mcp.security.tests.streamable.sync.server;

import org.springaicommunity.mcp.security.tests.AllowAllCorsConfigurationSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import static org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer.mcpServerOAuth2;

@Configuration
@EnableWebSecurity
@Import(GreeterTool.class)
public class StreamableHttpMcpServer {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http,
			@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUrl,
			@Value("${mcp.server.validate-audience-claim:false}") boolean validateAudienceClaim,
			@Value("${mcp.server.bind-session:false}") boolean bindSession) {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.with(mcpServerOAuth2(), (mcpAuthorization) -> {
				mcpAuthorization.authorizationServer(issuerUrl);
				mcpAuthorization.validateAudienceClaim(validateAudienceClaim);
				mcpAuthorization.resourcePath("/mcp");
				if (bindSession) {
					mcpAuthorization.sessionBinding(Customizer.withDefaults());
				}
			})
			// MCP inspector
			.cors(cors -> cors.configurationSource(new AllowAllCorsConfigurationSource()))
			.csrf(CsrfConfigurer::disable)
			.build();
	}

}
