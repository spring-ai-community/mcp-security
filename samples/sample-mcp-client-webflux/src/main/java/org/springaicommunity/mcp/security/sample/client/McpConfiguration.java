package org.springaicommunity.mcp.security.sample.client;

import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2AuthorizationCodeExchangeFilterFunction;

import org.springframework.ai.mcp.customizer.McpSyncClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
class McpConfiguration {

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
