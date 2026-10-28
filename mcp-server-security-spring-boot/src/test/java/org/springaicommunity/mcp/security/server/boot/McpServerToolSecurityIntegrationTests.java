/*
 * Copyright 2026-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springaicommunity.mcp.security.server.boot;

import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientSseClientTransport;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpClientTransport;
import io.modelcontextprotocol.spec.McpSchema;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.McpToolParam;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end tests for {@link McpServerToolSecurityAutoConfiguration}, listing and
 * calling tools over HTTP against Spring AI MCP servers.
 *
 * @author Yongtae Choi
 */
class McpServerToolSecurityIntegrationTests {

	@Nested
	@SpringBootTest(classes = ToolsApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
			properties = "spring.ai.mcp.server.protocol=STREAMABLE")
	class Streamable extends ToolFilteringTests {

	}

	@Nested
	@SpringBootTest(classes = ToolsApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
			properties = "spring.ai.mcp.server.protocol=STATELESS")
	class Stateless extends ToolFilteringTests {

	}

	@Nested
	@SpringBootTest(classes = ToolsApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
			properties = "spring.ai.mcp.server.protocol=SSE")
	class Sse extends ToolFilteringTests {

		@Override
		boolean sse() {
			return true;
		}

	}

	@Nested
	@SpringBootTest(classes = ToolsApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
			properties = { "spring.ai.mcp.server.protocol=STREAMABLE",
					"spring.ai.mcp.server.security.tool-filter.enabled=false" })
	class Disabled {

		@LocalServerPort
		int port;

		@Test
		void anonymousSeesEveryTool() {
			assertThat(listTools(client(this.port, null, false))).containsExactlyInAnyOrder("public-tool", "user-tool",
					"admin-tool", "owner-tool");
		}

	}

	abstract static class ToolFilteringTests {

		@LocalServerPort
		int port;

		boolean sse() {
			return false;
		}

		List<String> listTools(@Nullable String username) {
			return McpServerToolSecurityIntegrationTests.listTools(client(username));
		}

		McpSyncClient client(@Nullable String username) {
			return McpServerToolSecurityIntegrationTests.client(this.port, username, sse());
		}

		@Test
		void anonymousSeesUnsecuredTools() {
			assertThat(listTools(null)).containsExactlyInAnyOrder("public-tool", "owner-tool");
		}

		@Test
		void userSeesUserTools() {
			assertThat(listTools("alice")).containsExactlyInAnyOrder("public-tool", "user-tool", "owner-tool");
		}

		@Test
		void adminSeesEveryToolThroughRoleHierarchy() {
			assertThat(listTools("bob")).containsExactlyInAnyOrder("public-tool", "user-tool", "admin-tool",
					"owner-tool");
		}

		@Test
		void hiddenToolCannotBeCalled() {
			try (McpSyncClient client = client("alice")) {
				client.initialize();

				var result = client.callTool(McpSchema.CallToolRequest.builder().name("admin-tool").build());

				assertThat(result.isError()).isTrue();
			}
		}

		@Test
		void visibleToolCanBeCalled() {
			try (McpSyncClient client = client("bob")) {
				client.initialize();

				var result = client.callTool(McpSchema.CallToolRequest.builder().name("admin-tool").build());

				assertThat(result.isError()).isFalse();
				assertThat(result.content()).first()
					.isInstanceOfSatisfying(McpSchema.TextContent.class,
							(content) -> assertThat(content.text()).contains("admin"));
			}
		}

		@Test
		void argumentDependentToolIsListedAndEnforcedOnCall() {
			try (McpSyncClient client = client("alice")) {
				client.initialize();

				var allowed = client.callTool(McpSchema.CallToolRequest.builder()
					.name("owner-tool")
					.arguments(Map.of("owner", "alice"))
					.build());
				var denied = client.callTool(McpSchema.CallToolRequest.builder()
					.name("owner-tool")
					.arguments(Map.of("owner", "bob"))
					.build());

				assertThat(allowed.isError()).isFalse();
				assertThat(denied.isError()).isTrue();
			}
		}

	}

	static List<String> listTools(McpSyncClient mcpClient) {
		try (McpSyncClient client = mcpClient) {
			client.initialize();
			return client.listTools().tools().stream().map(McpSchema.Tool::name).toList();
		}
	}

	static McpSyncClient client(int port, @Nullable String username, boolean sse) {
		var requestBuilder = HttpRequest.newBuilder();
		if (username != null) {
			var credentials = Base64.getEncoder()
				.encodeToString((username + ":password").getBytes(StandardCharsets.UTF_8));
			requestBuilder.header("Authorization", "Basic " + credentials);
		}
		var baseUrl = "http://localhost:" + port;
		McpClientTransport transport = sse
				? HttpClientSseClientTransport.builder(baseUrl).requestBuilder(requestBuilder).build()
				: HttpClientStreamableHttpTransport.builder(baseUrl).requestBuilder(requestBuilder).build();
		return McpClient.sync(transport).build();
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@EnableMethodSecurity
	static class ToolsApplication {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.authorizeHttpRequests((auth) -> auth.anyRequest().permitAll())
				.httpBasic(Customizer.withDefaults())
				.csrf(AbstractHttpConfigurer::disable)
				.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					User.withUsername("alice").password("{noop}password").roles("USER").build(),
					User.withUsername("bob").password("{noop}password").roles("ADMIN").build());
		}

		@Bean
		static RoleHierarchy roleHierarchy() {
			return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
		}

		@Bean
		Tools tools() {
			return new Tools();
		}

	}

	static class Tools {

		@McpTool(name = "public-tool", description = "Available to everyone")
		public String publicTool() {
			return "public";
		}

		@PreAuthorize("hasRole('USER')")
		@McpTool(name = "user-tool", description = "Available to users")
		public String userTool() {
			return "user";
		}

		@PreAuthorize("hasRole('ADMIN')")
		@McpTool(name = "admin-tool", description = "Available to admins")
		public String adminTool() {
			return "admin";
		}

		@PreAuthorize("#owner == authentication.name")
		@McpTool(name = "owner-tool", description = "Available to the owner")
		public String ownerTool(@McpToolParam(description = "The owner") String owner) {
			return "owner " + owner;
		}

	}

}
