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

package org.springaicommunity.mcp.security.client.boot;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import io.modelcontextprotocol.client.McpClient;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DefaultMcpOAuth2DcrClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2DcrClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ScopeStepUpMcpOAuth2DcrClientManager;

import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ResolvableType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link McpOAuth2ClientAutoConfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
class McpOAuth2ClientAutoConfigurationTests {

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoConfiguration.class));

	@Test
	void autoConfigurationRegistersProperties() {
		this.contextRunner.run(context -> {
			assertThat(context).hasSingleBean(McpOAuth2ClientProperties.class);
		});
	}

	@Test
	void defaults() {
		this.contextRunner.run(context -> {
			assertThat(context).doesNotHaveBean(McpMetadataDiscoveryService.class);
			assertThat(context).doesNotHaveBean(DynamicClientRegistrationService.class);
			assertThat(context).hasSingleBean(ClientRegistrationRepository.class)
				.getBean(ClientRegistrationRepository.class)
				.isInstanceOf(InMemoryMcpClientRegistrationRepository.class);
			assertThat(context).hasSingleBean(McpOAuth2DcrClientManager.class)
				.getBean(McpOAuth2DcrClientManager.class)
				.isInstanceOf(ScopeStepUpMcpOAuth2DcrClientManager.class);
		});
	}

	@Test
	void existingMcpClientRegistrationRepositoryScopeStepUp() {
		this.contextRunner.withUserConfiguration(CustomMcpClientRegistrationRepositoryConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(McpOAuth2DcrClientManager.class)
					.getBean(McpOAuth2DcrClientManager.class)
					.isInstanceOf(ScopeStepUpMcpOAuth2DcrClientManager.class);
			});
	}

	@Test
	void dynamicClientRegistrationDisabled() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=false")
			.run(context -> {
				assertThat(context).doesNotHaveBean(McpMetadataDiscoveryService.class);
				assertThat(context).doesNotHaveBean(DynamicClientRegistrationService.class);
			});
	}

	@Test
	void dynamicClientRegistrationDisabledScopeStepUp() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=false")
			.run(context -> {
				assertThat(context).hasSingleBean(McpOAuth2DcrClientManager.class)
					.getBean(McpOAuth2DcrClientManager.class)
					.isInstanceOf(ScopeStepUpMcpOAuth2DcrClientManager.class);
			});
	}

	@Test
	void dynamicClientRegistrationEnabledExplicitly() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=true")
			.run(context -> {
				assertThat(context).hasSingleBean(McpMetadataDiscoveryService.class);
				assertThat(context).hasSingleBean(DynamicClientRegistrationService.class);
			});
	}

	@Test
	void clientRegistrationRepositoryLoadsOAuth2ClientProperties() {
		this.contextRunner
			.withPropertyValues("spring.security.oauth2.client.registration.test.client-id=test-client-id",
					"spring.security.oauth2.client.registration.test.client-secret=test-client-secret",
					"spring.security.oauth2.client.registration.test.authorization-grant-type=client_credentials",
					"spring.security.oauth2.client.provider.test.token-uri=https://example.com/oauth2/token")
			.run(context -> {
				assertThat(context).hasSingleBean(McpClientRegistrationRepository.class);
				var repo = context.getBean(McpClientRegistrationRepository.class);
				assertThat(repo.findByRegistrationId("test")).isNotNull();
				assertThat(repo.findByRegistrationId("test").getClientId()).isEqualTo("test-client-id");
			});
	}

	@Test
	void backsOffClientRegistrationRepository() {
		this.contextRunner.withUserConfiguration(CustomClientRegistrationRepositoryConfiguration.class).run(context -> {
			assertThat(context).hasSingleBean(ClientRegistrationRepository.class);
			assertThat(context).doesNotHaveBean(McpClientRegistrationRepository.class);
			assertThat(context.getBean(ClientRegistrationRepository.class))
				.isSameAs(context.getBean(CustomClientRegistrationRepositoryConfiguration.class).customRepository);
		});
	}

	@Test
	void backsOffMetadataDiscoveryService() {
		this.contextRunner.withUserConfiguration(CustomMetadataDiscoveryServiceConfiguration.class).run(context -> {
			assertThat(context).hasSingleBean(McpMetadataDiscoveryService.class);
			assertThat(context.getBean(McpMetadataDiscoveryService.class))
				.isSameAs(context.getBean(CustomMetadataDiscoveryServiceConfiguration.class).customService);
		});
	}

	@Test
	void backsOffDynamicClientRegistrationService() {
		this.contextRunner.withUserConfiguration(CustomDynamicClientRegistrationServiceConfiguration.class)
			.run(context -> {
				assertThat(context).hasSingleBean(DynamicClientRegistrationService.class);
				assertThat(context.getBean(DynamicClientRegistrationService.class))
					.isSameAs(context.getBean(CustomDynamicClientRegistrationServiceConfiguration.class).customService);
			});
	}

	@Test
	void backsOffMcpOAuth2ClientManager() {
		this.contextRunner.withUserConfiguration(CustomMcpOAuth2ClientManagerConfiguration.class).run(context -> {
			assertThat(context).hasSingleBean(McpOAuth2DcrClientManager.class);
			assertThat(context).doesNotHaveBean(DefaultMcpOAuth2DcrClientManager.class);
			assertThat(context).doesNotHaveBean(ScopeStepUpMcpOAuth2DcrClientManager.class);
			assertThat(context.getBean(McpOAuth2DcrClientManager.class))
				.isSameAs(context.getBean(CustomMcpOAuth2ClientManagerConfiguration.class).customManager);
		});
	}

	@Test
	@SuppressWarnings("unchecked")
	void registersMcpClientTransportContextProviderCustomizer() {
		this.contextRunner.run(context -> {
			assertThat(context).hasBean("mcpClientTransportContextProviderCustomizer");
			assertThat(context).hasSingleBean(McpClientCustomizer.class);
			var customizer = (McpClientCustomizer<McpClient.SyncSpec>) context
				.getBean("mcpClientTransportContextProviderCustomizer");
			assertThat(customizer).isNotNull();
		});
	}

	@Test
	void nonServlet() {
		new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoConfiguration.class))
			.run(context -> {
				assertThat(context).doesNotHaveBean(McpOAuth2DcrClientManager.class);
				assertThat(context).doesNotHaveBean(McpOAuth2ClientProperties.class);
				assertThat(context).doesNotHaveBean(McpClientRegistrationRepository.class);
			});
	}

	@Test
	void existingClientRegistrationRepository() {
		this.contextRunner.withUserConfiguration(CustomClientRegistrationRepositoryConfiguration.class).run(context -> {
			assertThat(context).doesNotHaveBean(McpOAuth2DcrClientManager.class);
			assertThat(context).doesNotHaveBean(DefaultMcpOAuth2DcrClientManager.class);
			assertThat(context).doesNotHaveBean(ScopeStepUpMcpOAuth2DcrClientManager.class);
			assertThat(context).doesNotHaveBean(OAuth2AccessTokenResponseClient.class);
		});
	}

	@Test
	void registersRefreshTokenTokenResponseClient() {
		this.contextRunner.run(context -> {
			var beanNames = context.getBeanNamesForType(ResolvableType
				.forClassWithGenerics(OAuth2AccessTokenResponseClient.class, OAuth2RefreshTokenGrantRequest.class));
			assertThat(beanNames).hasSize(1);
			assertThat(context.getBean(beanNames[0])).isInstanceOf(RestClientRefreshTokenTokenResponseClient.class);
		});
	}

	@Test
	void backsOffRefreshTokenTokenResponseClient() {
		this.contextRunner.withUserConfiguration(CustomRefreshTokenResponseClientConfiguration.class).run(context -> {
			var beanNames = context.getBeanNamesForType(ResolvableType
				.forClassWithGenerics(OAuth2AccessTokenResponseClient.class, OAuth2RefreshTokenGrantRequest.class));
			assertThat(beanNames).hasSize(1);
			assertThat(context.getBean(beanNames[0]))
				.isSameAs(context.getBean(CustomRefreshTokenResponseClientConfiguration.class).customClient);
		});
	}

	@Test
	void authorizedClientManagerUsesMcpRefreshTokenClientWithResource() throws IOException {
		AtomicReference<String> requestBody = new AtomicReference<>();
		HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
		server.createContext("/oauth2/token", exchange -> {
			requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
			byte[] response = "{\"access_token\":\"refreshed-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
				.getBytes(StandardCharsets.UTF_8);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(200, response.length);
			exchange.getResponseBody().write(response);
			exchange.close();
		});
		server.start();
		try {
			int port = server.getAddress().getPort();
			String resource = "https://mcp.example.com/mcp";
			ClientRegistration registration = ClientRegistration.withRegistrationId("test")
				.clientId("test-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("https://app.example.com/callback")
				.authorizationUri("https://auth.example.com/oauth2/authorize")
				.tokenUri("http://127.0.0.1:" + port + "/oauth2/token")
				.build();

			var repository = new InMemoryMcpClientRegistrationRepository();
			repository.addClientRegistration(registration, resource);
			var authorizedClientService = new InMemoryOAuth2AuthorizedClientService(repository);
			var authorizedClientRepository = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
					authorizedClientService);
			var principal = new TestingAuthenticationToken("test-user", "n/a");
			principal.setAuthenticated(true);

			var expiredAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "expired-token",
					Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));
			var refreshToken = new OAuth2RefreshToken("initial-refresh-token", Instant.now().minusSeconds(120));
			authorizedClientService.saveAuthorizedClient(
					new OAuth2AuthorizedClient(registration, principal.getName(), expiredAccessToken, refreshToken),
					principal);

			this.contextRunner.withBean(McpClientRegistrationRepository.class, () -> repository)
				.withBean(OAuth2AuthorizedClientRepository.class, () -> authorizedClientRepository)
				.withUserConfiguration(WebSecurityOAuth2ClientConfiguration.class)
				.run(context -> {
					var authorizedClientManager = context.getBean(OAuth2AuthorizedClientManager.class);
					var authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("test")
						.principal(principal)
						.attribute("jakarta.servlet.http.HttpServletRequest", new MockHttpServletRequest())
						.attribute("jakarta.servlet.http.HttpServletResponse", new MockHttpServletResponse())
						.build();

					var refreshedClient = authorizedClientManager.authorize(authorizeRequest);
					assertThat(refreshedClient).isNotNull();
					assertThat(refreshedClient.getAccessToken().getTokenValue()).isEqualTo("refreshed-token");

					String decodedBody = URLDecoder.decode(requestBody.get(), StandardCharsets.UTF_8);
					assertThat(decodedBody).contains("grant_type=refresh_token")
						.contains("refresh_token=initial-refresh-token")
						.contains("resource=" + resource);
				});
		}
		finally {
			server.stop(0);
		}
	}

	@Configuration
	static class CustomClientRegistrationRepositoryConfiguration {

		private final ClientRegistrationRepository customRepository = mock(ClientRegistrationRepository.class);

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return customRepository;
		}

	}

	@Configuration
	static class CustomMcpClientRegistrationRepositoryConfiguration {

		private final McpClientRegistrationRepository customRepository = mock(McpClientRegistrationRepository.class);

		@Bean
		McpClientRegistrationRepository mcpClientRegistrationRepository() {
			return customRepository;
		}

	}

	@Configuration
	static class CustomMetadataDiscoveryServiceConfiguration {

		final McpMetadataDiscoveryService customService = new McpMetadataDiscoveryService();

		@Bean
		McpMetadataDiscoveryService mcpMetadataDiscoveryService() {
			return this.customService;
		}

	}

	@Configuration
	static class CustomDynamicClientRegistrationServiceConfiguration {

		final DynamicClientRegistrationService customService = new DynamicClientRegistrationService();

		@Bean
		DynamicClientRegistrationService dynamicClientRegistrationService() {
			return this.customService;
		}

	}

	@Configuration
	static class CustomMcpOAuth2ClientManagerConfiguration {

		final McpOAuth2DcrClientManager customManager = mock(McpOAuth2DcrClientManager.class);

		@Bean
		McpOAuth2DcrClientManager mcpOAuth2ClientManager() {
			return this.customManager;
		}

	}

	@Configuration
	static class CustomRefreshTokenResponseClientConfiguration {

		@SuppressWarnings("unchecked")
		final OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> customClient = mock(
				OAuth2AccessTokenResponseClient.class);

		@Bean
		OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> customRefreshTokenResponseClient() {
			return this.customClient;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityOAuth2ClientConfiguration {

	}

}
