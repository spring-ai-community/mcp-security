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

/**
 * @author Daniel Garnier-Moiroux
 */
public class McpOAuth2ClientCredentialsExchangeFilterFunction implements ExchangeFilterFunction {

	private final ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialTokenProvider = new ClientCredentialsOAuth2AuthorizedClientProvider();

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final String clientRegistrationId;

	public McpOAuth2ClientCredentialsExchangeFilterFunction(OAuth2AuthorizedClientManager clientManager,
			ClientRegistrationRepository clientRegistrationRepository, String clientRegistrationId) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.clientRegistrationId = clientRegistrationId;
	}

	/**
	 * TODO
	 */
	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		// TODO: use AuthorizedClientServiceOAuth2AuthorizedClientManager instead
		var accessToken = getClientCredentialsAccessToken();
		var requestWithToken = ClientRequest.from(request)
			.headers(headers -> headers.setBearerAuth(accessToken))
			.build();
		return next.exchange(requestWithToken);
	}

	private String getClientCredentialsAccessToken() {
		var clientRegistration = this.clientRegistrationRepository.findByRegistrationId(this.clientRegistrationId);

		var authRequest = OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
			.principal(new AnonymousAuthenticationToken("client-credentials-client", "client-credentials-client",
					AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")))
			.build();
		return this.clientCredentialTokenProvider.authorize(authRequest).getAccessToken().getTokenValue();
	}

}
