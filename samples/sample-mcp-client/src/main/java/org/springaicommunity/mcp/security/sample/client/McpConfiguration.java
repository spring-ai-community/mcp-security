package org.springaicommunity.mcp.security.sample.client;

import io.modelcontextprotocol.client.transport.SyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@Configuration
class McpConfiguration {

	@Bean
	SyncHttpRequestCustomizer requestCustomizer(OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository) {
		var registrationId = findUniqueClientRegistration(clientRegistrationRepository);
		var requestCustomizer = new OAuth2AuthorizationCodeSyncHttpRequestCustomizer(oAuth2AuthorizedClientManager,
				registrationId);
		requestCustomizer.setFailOnMissingServletRequest(false);
		return requestCustomizer;
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
