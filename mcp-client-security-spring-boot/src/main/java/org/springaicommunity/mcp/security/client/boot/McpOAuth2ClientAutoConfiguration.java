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

import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.McpMetadataDiscoveryService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.DynamicClientRegistrationService;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpOAuth2ClientManager;

import org.springframework.ai.mcp.client.common.autoconfigure.properties.McpClientCommonProperties;
import org.springframework.ai.mcp.customizer.McpClientCustomizer;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.context.annotation.Import;

/**
 * {@link AutoConfiguration Auto-configuration} for MCP OAuth2 Client support. Registers
 * the following beans:
 * <ul>
 * <li>{@link McpClientRegistrationRepository}
 * <li>{@link DynamicClientRegistrationService}
 * <li>{@link McpMetadataDiscoveryService}
 * <li>{@link McpOAuth2ClientManager}
 * <li>A {@link McpClientCustomizer} to add
 * {@link AuthenticationMcpTransportContextProvider} to all sync clients.
 * </ul>
 * Only enabled for {@code SYNC} clients.
 *
 * @author Daniel Garnier-Moiroux
 */
@AutoConfiguration(before = OAuth2ClientAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties({ McpOAuth2ClientProperties.class, OAuth2ClientProperties.class })
@Import({ McpOAuth2ClientConfigurations.ClientRegistrationRepositoryConfiguration.class,
		McpOAuth2ClientConfigurations.DynamicClientRegistrationConfiguration.class,
		McpOAuth2ClientConfigurations.OAuth2ClientManagerConfiguration.class,
		McpOAuth2ClientConfigurations.McpClientConfiguration.class })
@ConditionalOnProperty(prefix = McpClientCommonProperties.CONFIG_PREFIX, name = "type", havingValue = "SYNC",
		matchIfMissing = true)
class McpOAuth2ClientAutoConfiguration {

}
