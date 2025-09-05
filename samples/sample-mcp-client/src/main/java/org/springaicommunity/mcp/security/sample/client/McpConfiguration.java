package org.springaicommunity.mcp.security.sample.client;

import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;

import org.springframework.ai.mcp.customizer.McpSyncClientCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@Configuration
class McpConfiguration {

	@Bean
	McpSyncHttpClientRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository) {
		var registrationId = findUniqueClientRegistration(clientRegistrationRepository);
		var requestCustomizer = new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(oAuth2AuthorizedClientManager,
				registrationId);
		requestCustomizer.setFailOnMissingServletRequest(false);
		return requestCustomizer;
	}

	@Bean
	McpSyncClientCustomizer syncClientCustomizer() {
		return (name, syncSpec) -> syncSpec.transportContextProvider(new AuthenticationMcpTransportContextProvider());
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
