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

import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

/**
 * @author Daniel Garnier-Moiroux
 */
public class McpOAuth2HybridExchangeFilterFunction implements ExchangeFilterFunction {

	private static final Logger log = LoggerFactory.getLogger(McpOAuth2HybridExchangeFilterFunction.class);

	private final ServletOAuth2AuthorizedClientExchangeFilterFunction delegate;

	private static final String AUTHENTICATION_ATTR_NAME = Authentication.class.getName();

	private static final String HTTP_SERVLET_REQUEST_ATTR_NAME = HttpServletRequest.class.getName();

	private static final String HTTP_SERVLET_RESPONSE_ATTR_NAME = HttpServletResponse.class.getName();

	private final AuthorizedClientServiceOAuth2AuthorizedClientManager serviceAuthorizedClientManager;

	private final String clientCredentialsClientRegistrationId;

	public McpOAuth2HybridExchangeFilterFunction(OAuth2AuthorizedClientManager clientManager,
			AuthorizedClientServiceOAuth2AuthorizedClientManager serviceAuthorizedClientManager,
			String authorizationCodeClientRegistrationId, String clientCredentialsClientRegistrationId) {
		this.delegate = new ServletOAuth2AuthorizedClientExchangeFilterFunction(clientManager);
		this.serviceAuthorizedClientManager = serviceAuthorizedClientManager;
		this.clientCredentialsClientRegistrationId = clientCredentialsClientRegistrationId;
		this.delegate.setDefaultClientRegistrationId(authorizationCodeClientRegistrationId);
	}

	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		return updateRequestWithMcpTransportContext(request).flatMap(req -> this.delegate.filter(req, next))
			.switchIfEmpty(Mono.defer(
					() -> getClientCredentialsAccessToken()
						.map(accessToken -> ClientRequest.from(request)
							.headers(headers -> headers.setBearerAuth(accessToken))
							.build())
						.flatMap(next::exchange)));
	}

	public Mono<ClientRequest> updateRequestWithMcpTransportContext(ClientRequest request) {
		return Mono.deferContextual(ctx -> {
			var transportContext = ctx.getOrDefault(McpTransportContext.KEY, McpTransportContext.EMPTY);
			var requestAttributes = transportContext
				.get(AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY);
			var authentication = transportContext.get(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY);

			if (!(requestAttributes instanceof ServletRequestAttributes ra) || authentication == null) {
				return Mono.empty();
			}

			var req = ClientRequest.from(request);
			req.attributes(attrs -> {
				attrs.putIfAbsent(HTTP_SERVLET_REQUEST_ATTR_NAME, ra.getRequest());
				attrs.putIfAbsent(HTTP_SERVLET_RESPONSE_ATTR_NAME, ra.getResponse());
				attrs.putIfAbsent(AUTHENTICATION_ATTR_NAME, authentication);
			});
			return Mono.just(req.build());
		});
	}

	private Mono<String> getClientCredentialsAccessToken() {
		log.debug("No authentication or request context found: requesting client_credentials token");

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(this.clientCredentialsClientRegistrationId)
			.principal("mcp-client-service")
			.build();
		// NOTE: 'serviceAuthorizedClientManager.authorize()' needs to be executed on a
		// dedicated
		// thread via subscribeOn(Schedulers.boundedElastic()) since it performs a
		// blocking I/O operation using RestClient internally
		return Mono.fromSupplier(() -> serviceAuthorizedClientManager.authorize(authorizeRequest))
			.map(OAuth2AuthorizedClient::getAccessToken)
			.map(AbstractOAuth2Token::getTokenValue);
	}

}
