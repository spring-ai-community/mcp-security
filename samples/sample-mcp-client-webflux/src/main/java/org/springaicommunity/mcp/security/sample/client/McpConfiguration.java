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

import java.util.List;

import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2AuthorizationCodeExchangeFilterFunction;

import org.springframework.ai.mcp.customizer.McpSyncClientCustomizer;
import org.springframework.ai.model.anthropic.autoconfigure.AnthropicChatAutoConfiguration;
import org.springframework.ai.model.tool.autoconfigure.ToolCallingAutoConfiguration;
import org.springframework.ai.tool.resolution.StaticToolCallbackResolver;
import org.springframework.ai.tool.resolution.ToolCallbackResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * @author Daniel Garnier-Moiroux
 */
@Configuration
class McpConfiguration {

	/**
	 * If the default {@link ToolCallbackResolver} from
	 * {@link ToolCallingAutoConfiguration} is imported, then all MCP-based tools are
	 * added to the resolver. In order to do so, the {@link ToolCallbackResolver} bean
	 * lists all MCP tools, therefore initializing MCP clients and listing the tools.
	 * <p>
	 * This is an issue when the MCP server is secured with OAuth2, because to obtain a
	 * token, a user must be involved in the flow, and there is no user present on app
	 * startup.
	 * <p>
	 * To avoid this issue, we must exclude the default {@link ToolCallbackResolver}. We
	 * can't easily disable the entire {@link ToolCallingAutoConfiguration} class, because
	 * it is imported directly by the chat model configurations, such as
	 * {@link AnthropicChatAutoConfiguration}. Instead, we provide a default, no-op bean.
	 */
	@Bean
	ToolCallbackResolver resolver() {
		return new StaticToolCallbackResolver(List.of());
	}

	@Bean
	McpSyncClientCustomizer syncClientCustomizer() {
		return (name, syncSpec) -> syncSpec.transportContextProvider(new AuthenticationMcpTransportContextProvider());
	}

	@Bean
	WebClient.Builder mcpWebClientBuilder(OAuth2AuthorizedClientManager clientManager) {
		return WebClient.builder()
			.filter(new McpOAuth2AuthorizationCodeExchangeFilterFunction(clientManager, "authserver"));
	}

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
