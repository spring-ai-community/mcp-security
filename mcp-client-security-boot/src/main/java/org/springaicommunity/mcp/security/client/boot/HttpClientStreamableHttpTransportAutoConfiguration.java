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

import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HttpClientTransportCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * {@link AutoConfiguration Auto-configuration} for MCP OAuth2 Client transport
 * customization when using {@link HttpClientStreamableHttpTransport}. Adds OAuth2
 * capabilities to the client transport, based on client
 * {@code spring.ai.mcp.client.authorization.dynamic-client-registration} as well as
 * existing Spring Security OAuth2 client registration.
 * <p>
 * If {@code spring.ai.mcp.client.authorization.dynamic-client-registration=false} and
 * there is a single client registration,
 * {@link OAuth2AuthorizationCodeSyncHttpRequestCustomizer} uses that registration for all
 * OAuth2 enabled calls. In case there are multiple registrations, then no customizer is
 * registered, and users should register their own customizer manually.
 * <p>
 * Only enabled for {@code SYNC} clients.
 *
 * @author Daniel Garnier-Moiroux
 */
@AutoConfiguration(after = { McpOAuth2ClientAutoConfiguration.class })
@ConditionalOnClass(HttpClientStreamableHttpTransport.class)
@ConditionalOnProperty(prefix = McpClientCommonProperties.CONFIG_PREFIX, name = "type", havingValue = "SYNC",
		matchIfMissing = true)
class HttpClientStreamableHttpTransportAutoConfiguration {

	private static final Logger log = LoggerFactory.getLogger(HttpClientStreamableHttpTransportAutoConfiguration.class);

	@Bean
	@ConditionalOnMissingBean
	@ConditionalOnBean({ ClientRegistrationRepository.class, McpOAuth2ClientManager.class })
	@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "dynamic-client-registration",
			havingValue = "true", matchIfMissing = true)
	OAuth2HttpClientTransportCustomizer dcrTransportCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, McpOAuth2ClientManager mcpOAuth2ClientManager) {
		log.debug("Configuring OAuth2 transport customizer with dynamic client registration support");
		return new OAuth2HttpClientTransportCustomizer(authorizedClientManager, clientRegistrationRepository,
				mcpOAuth2ClientManager);
	}

	@Bean
	@ConditionalOnMissingBean
	@ConditionalOnBean({ ClientRegistrationRepository.class })
	@ConditionalOnProperty(prefix = McpOAuth2ClientProperties.CONFIG_PREFIX, name = "dynamic-client-registration",
			havingValue = "false", matchIfMissing = false)
	McpClientCustomizer<HttpClientStreamableHttpTransport.Builder> preRegisteredClientCustomizer(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2ClientProperties clientRegistrationProperties,
			OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager) {

		var registrationIds = clientRegistrationProperties.getRegistration().keySet();
		if (registrationIds.size() == 1) {
			var registrationId = registrationIds.iterator().next();
			log.debug("Configuring pre-registered OAuth2 transport customizer with single registration '{}'",
					registrationId);
			return (name, transport) -> {
				var customizer = new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(oAuth2AuthorizedClientManager,
						clientRegistrationRepository, registrationId);
				customizer.disableDynamicClientRegistration(false);
				transport.httpRequestCustomizer(customizer);
			};
		}
		else {
			log.warn(
					"Found {} client registrations but expected exactly 1; "
							+ "skipping OAuth2 transport customization. Consider registering your own {} bean. "
							+ "Registrations found: {}",
					registrationIds.size(), OAuth2HttpClientTransportCustomizer.class.getSimpleName(), registrationIds);
			return (name, transport) -> {
			};
		}
	}

}
