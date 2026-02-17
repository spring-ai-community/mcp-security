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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client;

import java.net.URI;
import java.net.http.HttpRequest;

import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.AuthenticationMcpTransportContextProvider;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2HybridSyncHttpRequestCustomizer implements McpSyncHttpClientRequestCustomizer {

	private static final Logger log = LoggerFactory.getLogger(OAuth2HybridSyncHttpRequestCustomizer.class);

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private final AuthorizedClientServiceOAuth2AuthorizedClientManager serviceAuthorizedClientManager;

	private final String authorizationCodeClientRegistrationId;

	private final String clientCredentialsClientRegistrationId;

	public OAuth2HybridSyncHttpRequestCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			AuthorizedClientServiceOAuth2AuthorizedClientManager serviceAuthorizedClientManager,
			String authorizationCodeClientRegistrationId, String clientCredentialsClientRegistrationId) {
		this.authorizedClientManager = authorizedClientManager;
		this.serviceAuthorizedClientManager = serviceAuthorizedClientManager;
		this.authorizationCodeClientRegistrationId = authorizationCodeClientRegistrationId;
		this.clientCredentialsClientRegistrationId = clientCredentialsClientRegistrationId;
	}

	@Override
	public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body,
			McpTransportContext context) {
		var accessToken = getAccessToken(context);
		log.debug("Obtained access token");
		builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

	public OAuth2AccessToken getAccessToken(McpTransportContext context) {
		var authentication = context.get(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY);
		var requestAttributes = context.get(AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY);

		if (!(requestAttributes instanceof ServletRequestAttributes attrs)) {
			OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId(this.clientCredentialsClientRegistrationId)
				.principal("mcp-client-service")
				.build();
			log.debug("No authentication or request context found: requesting client_credentials token");
			return serviceAuthorizedClientManager.authorize(authorizeRequest).getAccessToken();
		}

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(this.authorizationCodeClientRegistrationId)
			.principal((Authentication) authentication)
			.attribute(HttpServletRequest.class.getName(), attrs.getRequest())
			.attribute(HttpServletResponse.class.getName(), attrs.getResponse())
			.build();
		log.debug("Requesting access token");
		return this.authorizedClientManager.authorize(authorizeRequest).getAccessToken();

	}

}
