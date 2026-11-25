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

import io.modelcontextprotocol.client.McpClient;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.McpResourceParametersConverter;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DelegatingMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ScopeStepUpMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.CimdMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.dcr.DcrMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.dcr.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springaicommunity.mcp.security.common.url.UrlValidator;
import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientPropertiesMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Configurations for MCP OAuth2 Client support. Creates an
 * {@link McpClientRegistrationRepository} for storing client registrations for MCP
 * clients, as well as the infrastructure to register clients with Client ID Metadata
 * Documents (CIMD) and dynamic client registration (DCR). When both are enabled, CIMD is
 * tried first, then DCR.
 * <p>
 * CIMD is enabled by default, and can be turned off via
 * {@code spring.ai.mcp.client.authorization.cimd.enabled=false}. DCR is disabled by
 * default, and can be turned on via
 * {@code spring.ai.mcp.client.authorization.dynamic-client-registration.enabled=true}.
 * <p>
 * If client registrations are found under
 * {@code spring.security.oauth2.client.registration}, they are add to the
 * {@link McpClientRegistrationRepository}, but the OAuth2 resource identifier associated
 * will be null.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP
 * Specification: authorization</a>
 */
class McpOAuth2ClientConfigurations {

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnMissingBean(ClientRegistrationRepository.class)
	static class ClientRegistrationRepositoryConfiguration {

		@Bean
		McpClientRegistrationRepository mcpClientRegistrationRepository(OAuth2ClientProperties properties) {
			var repo = new InMemoryMcpClientRegistrationRepository();
			new OAuth2ClientPropertiesMapper(properties).asClientRegistrations()
				.values()
				.forEach(reg -> repo.save(reg, null));
			return repo;
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class McpMetadataDiscoveryConfiguration {

		@Bean
		@ConditionalOnMissingBean
		UrlValidator urlValidator(McpOAuth2ClientProperties properties) {
			return new DefaultUrlValidator(properties.isAllowLoopbackAddresses());
		}

		@Bean
		@ConditionalOnMissingBean
		McpMetadataDiscoveryService mcpMetadataDiscoveryService(UrlValidator urlValidator) {
			return new McpMetadataDiscoveryService(urlValidator);
		}

	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX,
			name = "dynamic-client-registration.enabled", havingValue = "true")
	static class DynamicClientRegistrationConfiguration {

		@Bean
		@ConditionalOnMissingBean
		DynamicClientRegistrationService dynamicClientRegistrationService(UrlValidator urlValidator) {
			return new DynamicClientRegistrationService(urlValidator);
		}

	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnBean(McpClientRegistrationRepository.class)
	@ConditionalOnMissingBean(McpOAuth2ClientManager.class)
	static class OAuth2ClientManagerConfiguration {

		@Bean
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "cimd.enabled",
				havingValue = "true", matchIfMissing = true)
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX,
				name = "dynamic-client-registration.enabled", havingValue = "false", matchIfMissing = true)
		@ConditionalOnBean({ McpMetadataDiscoveryService.class, UrlValidator.class })
		@ConditionalOnMissingBean(McpOAuth2ClientManager.class)
		CimdMcpOAuth2ClientManager cimdMcpOAuth2ClientManager(
				McpClientRegistrationRepository mcpClientRegistrationRepository,
				McpMetadataDiscoveryService mcpMetadataDiscoveryService, UrlValidator urlValidator) {
			return new CimdMcpOAuth2ClientManager(mcpMetadataDiscoveryService, mcpClientRegistrationRepository,
					urlValidator);
		}

		@Bean
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "cimd.enabled",
				havingValue = "false", matchIfMissing = false)
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX,
				name = "dynamic-client-registration.enabled", havingValue = "true", matchIfMissing = false)
		@ConditionalOnBean({ DynamicClientRegistrationService.class, McpMetadataDiscoveryService.class,
				UrlValidator.class })
		DcrMcpOAuth2ClientManager dcrMcpOAuth2ClientManager(
				McpClientRegistrationRepository mcpClientRegistrationRepository,
				DynamicClientRegistrationService dynamicClientRegistrationService,
				McpMetadataDiscoveryService mcpMetadataDiscoveryService, UrlValidator urlValidator) {
			return new DcrMcpOAuth2ClientManager(mcpClientRegistrationRepository, dynamicClientRegistrationService,
					mcpMetadataDiscoveryService, urlValidator);
		}

		@Bean
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "cimd.enabled",
				havingValue = "true", matchIfMissing = true)
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX,
				name = "dynamic-client-registration.enabled", havingValue = "true", matchIfMissing = false)
		@ConditionalOnBean({ DynamicClientRegistrationService.class, McpMetadataDiscoveryService.class,
				UrlValidator.class })
		DelegatingMcpOAuth2ClientManager defaultmcpOauth2ClientManager(
				McpClientRegistrationRepository mcpClientRegistrationRepository,
				DynamicClientRegistrationService dynamicClientRegistrationService,
				McpMetadataDiscoveryService mcpMetadataDiscoveryService, UrlValidator urlValidator) {
			var cimd = new CimdMcpOAuth2ClientManager(mcpMetadataDiscoveryService, mcpClientRegistrationRepository,
					urlValidator);
			var dcr = new DcrMcpOAuth2ClientManager(mcpClientRegistrationRepository, dynamicClientRegistrationService,
					mcpMetadataDiscoveryService, urlValidator);
			return new DelegatingMcpOAuth2ClientManager(cimd, dcr);
		}

		@Bean
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "cimd.enabled",
				havingValue = "false", matchIfMissing = false)
		@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX,
				name = "dynamic-client-registration.enabled", havingValue = "false", matchIfMissing = true)
		@ConditionalOnMissingBean({ DynamicClientRegistrationService.class })
		ScopeStepUpMcpOAuth2ClientManager scopeStepUpMcpOAuth2ClientManager(
				McpClientRegistrationRepository mcpClientRegistrationRepository) {
			return new ScopeStepUpMcpOAuth2ClientManager(mcpClientRegistrationRepository);
		}

	}

	/**
	 * Adds the RFC 8707 {@code resource} parameter to refresh token requests. Spring
	 * Security's default {@link OAuth2AuthorizedClientManager} uses this
	 * {@link OAuth2AccessTokenResponseClient} when it refreshes tokens.
	 * <p>
	 * Backs off when a {@link RefreshTokenOAuth2AuthorizedClientProvider} bean is
	 * defined: Spring Security would otherwise override that provider's response client
	 * with this one.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnBean(McpClientRegistrationRepository.class)
	@ConditionalOnMissingBean(RefreshTokenOAuth2AuthorizedClientProvider.class)
	static class RefreshTokenConfiguration {

		@Bean
		@ConditionalOnMissingBean
		OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> mcpRefreshTokenResponseClient(
				McpClientRegistrationRepository mcpClientRegistrationRepository) {
			var client = new RestClientRefreshTokenTokenResponseClient();
			client.addParametersConverter(new McpResourceParametersConverter<>(mcpClientRegistrationRepository));
			return client;
		}

	}

	/**
	 * Adds the RFC 8707 {@code resource} parameter to client credentials token requests.
	 * Spring Security's default {@link OAuth2AuthorizedClientManager} uses this
	 * {@link OAuth2AccessTokenResponseClient} for the {@code client_credentials} grant.
	 * <p>
	 * Backs off when a {@link ClientCredentialsOAuth2AuthorizedClientProvider} bean is
	 * defined: Spring Security would otherwise override that provider's response client
	 * with this one.
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnBean(McpClientRegistrationRepository.class)
	@ConditionalOnMissingBean(ClientCredentialsOAuth2AuthorizedClientProvider.class)
	static class ClientCredentialsConfiguration {

		@Bean
		@ConditionalOnMissingBean
		OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> mcpClientCredentialsTokenResponseClient(
				McpClientRegistrationRepository mcpClientRegistrationRepository) {
			var client = new RestClientClientCredentialsTokenResponseClient();
			client.addParametersConverter(new McpResourceParametersConverter<>(mcpClientRegistrationRepository));
			return client;
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class McpClientConfiguration {

		@Bean
		@ConditionalOnMissingBean
		McpClientCustomizer<McpClient.SyncSpec> mcpClientTransportContextProviderCustomizer() {
			return (name, client) -> client.transportContextProvider(new AuthenticationMcpTransportContextProvider());
		}

	}

}
