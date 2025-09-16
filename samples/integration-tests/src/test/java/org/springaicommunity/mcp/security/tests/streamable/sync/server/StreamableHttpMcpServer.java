package org.springaicommunity.mcp.security.tests.streamable.sync.server;

import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.server.McpStatelessServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;
import org.springaicommunity.mcp.security.tests.AllowAllCorsConfigurationSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import static org.springaicommunity.mcp.security.resourceserver.config.McpResourceServerConfigurer.mcpServerAuthorization;

@Configuration
@EnableWebSecurity
public class StreamableHttpMcpServer {

	private McpSchema.Tool TOOL = McpSchema.Tool.builder()
		.name("greeter")
		.description("Greets you nicely!")
		.inputSchema(new McpSchema.JsonSchema("object", null, null, null, null, null))
		.build();

	@Bean
	@ConditionalOnProperty(name = "spring.ai.mcp.server.protocol", havingValue = "STREAMABLE")
	List<McpServerFeatures.SyncToolSpecification> streamableTools() {
		McpServerFeatures.SyncToolSpecification tool = McpServerFeatures.SyncToolSpecification.builder()
			.tool(TOOL)
			.callHandler((exchange, request) -> {
				var authentication = SecurityContextHolder.getContext().getAuthentication();
				return McpSchema.CallToolResult.builder()
					.textContent(List.of("Hello " + authentication.getName()))
					.build();
			})
			.build();

		return List.of(tool);
	}

	@Bean
	@ConditionalOnProperty(name = "spring.ai.mcp.server.protocol", havingValue = "STATELESS")
	List<McpStatelessServerFeatures.SyncToolSpecification> statelessTools() {
		McpStatelessServerFeatures.SyncToolSpecification tool = McpStatelessServerFeatures.SyncToolSpecification
			.builder()
			.tool(TOOL)
			.callHandler((exchange, request) -> {
				var authentication = SecurityContextHolder.getContext().getAuthentication();
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
		return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.with(mcpServerAuthorization(), (mcpAuthorization) -> {
				mcpAuthorization.authorizationServer(issuerUrl).resourceIdentifier("http://localhost:8092/mcp");
			})
			// MCP inspector
			.cors(cors -> cors.configurationSource(new AllowAllCorsConfigurationSource()))
			.csrf(CsrfConfigurer::disable)

			.build();
	}

}
