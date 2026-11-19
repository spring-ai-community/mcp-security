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

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import io.modelcontextprotocol.client.McpClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.servlet.OAuth2ClientWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.AbstractRestClientOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link McpOAuth2ClientAutoConfiguration}.
 *
 * @author Daniel Garnier-Moiroux
 */
class McpOAuth2ClientAutoConfigurationTests {

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(McpOAuth2ClientAutoConfiguration.class));

	private final WebApplicationContextRunner securityContextRunner = this.contextRunner.withConfiguration(
			AutoConfigurations.of(OAuth2ClientAutoConfiguration.class, OAuth2ClientWebSecurityAutoConfiguration.class,
					SecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class));

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
	void refreshTokenResponseClientSendsResource() {
		this.contextRunner.run(context -> {
			var registration = addMcpRegistration(context, AuthorizationGrantType.AUTHORIZATION_CODE);
			var client = context.getBean("mcpRefreshTokenResponseClient",
					RestClientRefreshTokenTokenResponseClient.class);
			var server = mockTokenEndpoint(client, "refresh_token");

			var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", null, null);
			var refreshToken = new OAuth2RefreshToken("refresh-token", null);
			var response = client
				.getTokenResponse(new OAuth2RefreshTokenGrantRequest(registration, accessToken, refreshToken));

			assertThat(response.getAccessToken().getTokenValue()).isEqualTo("new-access-token");
			server.verify();
		});
	}

	@Test
	void clientCredentialsTokenResponseClientSendsResource() {
		this.contextRunner.run(context -> {
			var registration = addMcpRegistration(context, AuthorizationGrantType.CLIENT_CREDENTIALS);
			var client = context.getBean("mcpClientCredentialsTokenResponseClient",
					RestClientClientCredentialsTokenResponseClient.class);
			var server = mockTokenEndpoint(client, "client_credentials");

			var response = client.getTokenResponse(new OAuth2ClientCredentialsGrantRequest(registration));

			assertThat(response.getAccessToken().getTokenValue()).isEqualTo("new-access-token");
			server.verify();
		});
	}

	@Test
	void authorizedClientManagerRefreshSendsResource() {
		this.securityContextRunner.run(context -> {
			var registration = addMcpRegistration(context, AuthorizationGrantType.AUTHORIZATION_CODE);
			var server = mockTokenEndpoint(
					context.getBean("mcpRefreshTokenResponseClient", RestClientRefreshTokenTokenResponseClient.class),
					"refresh_token");
			var expiredAccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
					Instant.now().minus(Duration.ofHours(2)), Instant.now().minus(Duration.ofHours(1)));
			var authorizedClient = new OAuth2AuthorizedClient(registration, "user", expiredAccessToken,
					new OAuth2RefreshToken("refresh-token", null));

			var refreshed = context.getBean(OAuth2AuthorizedClientManager.class)
				.authorize(authorizeRequest(OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient)));

			assertThat(refreshed).isNotNull();
			assertThat(refreshed.getAccessToken().getTokenValue()).isEqualTo("new-access-token");
			server.verify();
		});
	}

	@Test
	void authorizedClientManagerClientCredentialsSendsResource() {
		this.securityContextRunner.run(context -> {
			addMcpRegistration(context, AuthorizationGrantType.CLIENT_CREDENTIALS);
			var server = mockTokenEndpoint(context.getBean("mcpClientCredentialsTokenResponseClient",
					RestClientClientCredentialsTokenResponseClient.class), "client_credentials");

			var authorized = context.getBean(OAuth2AuthorizedClientManager.class)
				.authorize(authorizeRequest(OAuth2AuthorizeRequest.withClientRegistrationId("mcp-server")));

			assertThat(authorized).isNotNull();
			assertThat(authorized.getAccessToken().getTokenValue()).isEqualTo("new-access-token");
			server.verify();
		});
	}

	@Test
	void registersTokenResponseClients() {
		this.contextRunner.run(context -> assertThat(context).getBeans(OAuth2AccessTokenResponseClient.class)
			.containsOnlyKeys("mcpRefreshTokenResponseClient", "mcpClientCredentialsTokenResponseClient"));
	}

	@Test
	void backsOffRefreshTokenResponseClient() {
		this.contextRunner.withUserConfiguration(CustomRefreshTokenResponseClientConfiguration.class)
			.run(context -> assertThat(context).getBeans(OAuth2AccessTokenResponseClient.class)
				.containsOnlyKeys("refreshTokenResponseClient", "mcpClientCredentialsTokenResponseClient"));
	}

	@Test
	void backsOffRefreshTokenResponseClientWithCustomRefreshTokenProvider() {
		this.contextRunner.withUserConfiguration(CustomRefreshTokenProviderConfiguration.class)
			.run(context -> assertThat(context).getBeans(OAuth2AccessTokenResponseClient.class)
				.containsOnlyKeys("mcpClientCredentialsTokenResponseClient"));
	}

	@Test
	void backsOffClientCredentialsTokenResponseClient() {
		this.contextRunner.withUserConfiguration(CustomClientCredentialsResponseClientConfiguration.class)
			.run(context -> assertThat(context).getBeans(OAuth2AccessTokenResponseClient.class)
				.containsOnlyKeys("clientCredentialsResponseClient", "mcpRefreshTokenResponseClient"));
	}

	@Test
	void backsOffClientCredentialsTokenResponseClientWithCustomClientCredentialsProvider() {
		this.contextRunner.withUserConfiguration(CustomClientCredentialsProviderConfiguration.class)
			.run(context -> assertThat(context).getBeans(OAuth2AccessTokenResponseClient.class)
				.containsOnlyKeys("mcpRefreshTokenResponseClient"));
	}

	@Test
	void noTokenResponseClientsWithoutMcpClientRegistrationRepository() {
		this.contextRunner.withUserConfiguration(CustomClientRegistrationRepositoryConfiguration.class)
			.run(context -> assertThat(context).doesNotHaveBean(OAuth2AccessTokenResponseClient.class));
	}

	private static ClientRegistration addMcpRegistration(ApplicationContext context, AuthorizationGrantType grantType) {
		var builder = ClientRegistration.withRegistrationId("mcp-server")
			.clientId("client-id")
			.authorizationGrantType(grantType)
			.tokenUri("https://auth.example.com/token");
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grantType)) {
			builder.redirectUri("http://localhost/callback").authorizationUri("https://auth.example.com/authorize");
		}
		var registration = builder.build();
		context.getBean(McpClientRegistrationRepository.class)
			.addClientRegistration(registration, "https://mcp.example.com/mcp");
		return registration;
	}

	private static OAuth2AuthorizeRequest authorizeRequest(OAuth2AuthorizeRequest.Builder builder) {
		return builder.principal("user")
			.attribute(HttpServletRequest.class.getName(), new MockHttpServletRequest())
			.attribute(HttpServletResponse.class.getName(), new MockHttpServletResponse())
			.build();
	}

	private static MockRestServiceServer mockTokenEndpoint(AbstractRestClientOAuth2AccessTokenResponseClient<?> client,
			String grantType) {
		var restClient = RestClient.builder()
			.configureMessageConverters(converters -> converters.addCustomConverter(new FormHttpMessageConverter())
				.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter()));
		var server = MockRestServiceServer.bindTo(restClient).build();
		client.setRestClient(restClient.build());
		server.expect(request -> assertThat(request.getURI()).hasToString("https://auth.example.com/token"))
			.andExpect(content()
				.formDataContains(Map.of("grant_type", grantType, "resource", "https://mcp.example.com/mcp")))
			.andRespond(withSuccess("""
					{"access_token": "new-access-token", "token_type": "Bearer"}
					""", MediaType.APPLICATION_JSON));
		return server;
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
		});
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
	static class CustomRefreshTokenResponseClientConfiguration {

		@Bean
		OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenResponseClient() {
			return new RestClientRefreshTokenTokenResponseClient();
		}

	}

	@Configuration
	static class CustomRefreshTokenProviderConfiguration {

		@Bean
		RefreshTokenOAuth2AuthorizedClientProvider refreshTokenProvider() {
			return new RefreshTokenOAuth2AuthorizedClientProvider();
		}

	}

	@Configuration
	static class CustomClientCredentialsResponseClientConfiguration {

		@Bean
		OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsResponseClient() {
			return new RestClientClientCredentialsTokenResponseClient();
		}

	}

	@Configuration
	static class CustomClientCredentialsProviderConfiguration {

		@Bean
		ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsProvider() {
			return new ClientCredentialsOAuth2AuthorizedClientProvider();
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

}
