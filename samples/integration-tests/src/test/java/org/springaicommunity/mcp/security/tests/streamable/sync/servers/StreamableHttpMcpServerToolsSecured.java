package org.springaicommunity.mcp.security.tests.streamable.sync.servers;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;
import org.springaicommunity.mcp.security.tests.AllowAllCorsConfigurationSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import static org.springaicommunity.mcp.security.resourceserver.config.McpResourceServerConfigurer.mcpServerAuthorization;

/**
 * An MCP server where only tool calling is secured with OAuth2, and not connecting or
 * listing tools.
 */
@Configuration
@EnableWebSecurity
public class StreamableHttpMcpServerToolsSecured {

	private final AuthenticationTrustResolverImpl trustResolver = new AuthenticationTrustResolverImpl();

	@Bean
	List<McpServerFeatures.SyncToolSpecification> tools() {
		McpSchema.Tool greeterTool = McpSchema.Tool.builder()
			.name("greeter")
			.description("Greets you nicely!")
			.inputSchema(new McpSchema.JsonSchema("object", null, null, null, null, null))
			.build();

		McpServerFeatures.SyncToolSpecification tool = McpServerFeatures.SyncToolSpecification.builder()
			.tool(greeterTool)
			.callHandler((exchange, request) -> {
				var authentication = SecurityContextHolder.getContext().getAuthentication();
				if (trustResolver.isAnonymous(authentication)) {
					return McpSchema.CallToolResult.builder()
						.isError(true)
						.textContent(List.of("not authenticated"))
						.build();
				}
				return McpSchema.CallToolResult.builder()
					.textContent(List.of("Hello " + authentication.getName()))
					.build();
			})
			.build();

		return List.of(tool);
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http,
			@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUrl) throws Exception {
		return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
			.with(mcpServerAuthorization(), (mcpAuthorization) -> {
				// TODO
				mcpAuthorization.authorizationServer(issuerUrl).resourceIdentifier("http://localhost:8092/mcp");
			})
			// MCP inspector
			.cors(cors -> cors.configurationSource(new AllowAllCorsConfigurationSource()))
			.csrf(CsrfConfigurer::disable)

			.build();
	}

}
