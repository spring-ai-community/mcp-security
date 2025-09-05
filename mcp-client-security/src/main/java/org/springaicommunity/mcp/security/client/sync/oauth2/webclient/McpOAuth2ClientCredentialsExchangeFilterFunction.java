package org.springaicommunity.mcp.security.client.sync.oauth2.webclient;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

class McpOAuth2ClientCredentialsExchangeFilterFunction implements ExchangeFilterFunction {

	private final ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialTokenProvider = new ClientCredentialsOAuth2AuthorizedClientProvider();

	private final ClientRegistrationRepository clientRegistrationRepository;

	// TODO
	private static final String CLIENT_CREDENTIALS_CLIENT_REGISTRATION_ID = "authserver-client-credentials";

	public McpOAuth2ClientCredentialsExchangeFilterFunction(OAuth2AuthorizedClientManager clientManager,
			ClientRegistrationRepository clientRegistrationRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	/**
	 * TODO
	 */
	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		// TODO: polish
		var accessToken = getClientCredentialsAccessToken();
		var requestWithToken = ClientRequest.from(request)
			.headers(headers -> headers.setBearerAuth(accessToken))
			.build();
		return next.exchange(requestWithToken);
	}

	private String getClientCredentialsAccessToken() {
		var clientRegistration = this.clientRegistrationRepository
			.findByRegistrationId(CLIENT_CREDENTIALS_CLIENT_REGISTRATION_ID);

		var authRequest = OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
			.principal(new AnonymousAuthenticationToken("client-credentials-client", "client-credentials-client",
					AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")))
			.build();
		return this.clientCredentialTokenProvider.authorize(authRequest).getAccessToken().getTokenValue();
	}

}
