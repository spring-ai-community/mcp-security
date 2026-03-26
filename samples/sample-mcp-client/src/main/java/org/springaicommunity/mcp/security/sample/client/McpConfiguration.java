/*
 * Copyright 2025-2025 the original author or authors.
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

package org.springaicommunity.mcp.security.sample.client;

import io.modelcontextprotocol.client.McpClient;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HttpClientTransportCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DefaultMcpOAuth2ClientManager;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

/**
 * @author Daniel Garnier-Moiroux
 */
@Configuration
class McpConfiguration {

	@Bean
	McpClientCustomizer<McpClient.SyncSpec> syncClientCustomizer() {
		return (name, syncSpec) -> syncSpec.transportContextProvider(new AuthenticationMcpTransportContextProvider());
	}

	@Bean
	McpClientRegistrationRepository mcpClientRegistrationRepository() {
		return new InMemoryMcpClientRegistrationRepository();
	}

	@Bean
	McpOAuth2ClientManager mcpOAuth2ClientManager(McpClientRegistrationRepository mcpClientRegistrationRepository) {
		return new DefaultMcpOAuth2ClientManager(mcpClientRegistrationRepository,
				new DynamicClientRegistrationService(), new McpMetadataDiscoveryService());
	}

	@Bean
	OAuth2HttpClientTransportCustomizer transportCustomizer(OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, McpOAuth2ClientManager mcpOAuth2ClientManager) {
		return new OAuth2HttpClientTransportCustomizer(oAuth2AuthorizedClientManager, clientRegistrationRepository,
				mcpOAuth2ClientManager);
	}

	/**
	 * Returns the ID of the {@code spring.security.oauth2.client.registration}, if
	 * unique.
	 */
	private static String findUniqueClientRegistration(ClientRegistrationRepository clientRegistrationRepository) {
		String registrationId;
		if (!(clientRegistrationRepository instanceof InMemoryClientRegistrationRepository repo)) {
			throw new IllegalStateException("Expected an InMemoryClientRegistrationRepository");
		}
		var iterator = repo.iterator();
		var firstRegistration = iterator.next();
		if (iterator.hasNext()) {
			throw new IllegalStateException("Expected a single Client Registration");
		}
		registrationId = firstRegistration.getRegistrationId();
		return registrationId;
	}

}
