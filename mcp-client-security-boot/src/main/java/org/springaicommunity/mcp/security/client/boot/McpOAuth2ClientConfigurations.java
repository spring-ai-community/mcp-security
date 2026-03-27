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
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DefaultMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.ScopeStepUpMcpOAuth2ClientManager;

import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientPropertiesMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Configurations for MCP OAuth2 Client support. Creates an
 * {@link McpClientRegistrationRepository} for storing client registrations for MCP
 * clients, as well as the infrastructure to perform dynamic client registration (DCR).
 * <p>
 * DCR can be turned off via
 * {@code spring.ai.mcp.client.authorization.dynamic-client-registration=false}.
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
				.forEach(reg -> repo.addClientRegistration(reg, null));
			return repo;
		}

	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "dynamic-client-registration",
			havingValue = "true", matchIfMissing = true)
	static class DynamicClientRegistrationConfiguration {

		@Bean
		@ConditionalOnMissingBean
		McpMetadataDiscoveryService mcpMetadataDiscoveryService() {
			return new McpMetadataDiscoveryService();
		}

		@Bean
		@ConditionalOnMissingBean
		DynamicClientRegistrationService dynamicClientRegistrationService() {
			return new DynamicClientRegistrationService();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnBean(McpClientRegistrationRepository.class)
	@ConditionalOnMissingBean(McpOAuth2ClientManager.class)
	static class OAuth2ClientManagerConfiguration {

		@Bean
		@ConditionalOnBean({ DynamicClientRegistrationService.class, McpMetadataDiscoveryService.class, })
		DefaultMcpOAuth2ClientManager mcpOAuth2ClientManager(
				McpClientRegistrationRepository mcpClientRegistrationRepository,
				DynamicClientRegistrationService dynamicClientRegistrationService,
				McpMetadataDiscoveryService mcpMetadataDiscoveryService) {
			return new DefaultMcpOAuth2ClientManager(mcpClientRegistrationRepository, dynamicClientRegistrationService,
					mcpMetadataDiscoveryService);
		}

		@Bean
		@ConditionalOnMissingBean({ DynamicClientRegistrationService.class, McpMetadataDiscoveryService.class })
		ScopeStepUpMcpOAuth2ClientManager scopeStepUpMcpOAuth2ClientManager(
				McpClientRegistrationRepository mcpClientRegistrationRepository) {
			return new ScopeStepUpMcpOAuth2ClientManager(mcpClientRegistrationRepository);
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
