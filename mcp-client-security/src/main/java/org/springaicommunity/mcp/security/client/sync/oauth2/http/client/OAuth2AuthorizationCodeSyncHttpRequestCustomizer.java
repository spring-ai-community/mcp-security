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
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationCodeSyncHttpRequestCustomizer implements McpSyncHttpClientRequestCustomizer {

	private static final Logger log = LoggerFactory.getLogger(OAuth2AuthorizationCodeSyncHttpRequestCustomizer.class);

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private final String clientRegistrationId;

	public OAuth2AuthorizationCodeSyncHttpRequestCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			String clientRegistrationId) {
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationId = clientRegistrationId;
	}

	@Override
	public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body,
			McpTransportContext context) {
		if (!(context
			.get(AuthenticationMcpTransportContextProvider.AUTHENTICATION_KEY) instanceof Authentication authentication)
				|| !(context.get(
						AuthenticationMcpTransportContextProvider.REQUEST_ATTRIBUTES_KEY) instanceof ServletRequestAttributes requestAttributes)) {
			log.debug("No authentication or request context found: not requesting token");
			return;
		}

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(this.clientRegistrationId)
			.principal(authentication)
			.attribute(HttpServletRequest.class.getName(), requestAttributes.getRequest())
			.attribute(HttpServletResponse.class.getName(), requestAttributes.getResponse())
			.build();
		log.debug("Requesting access token");
		var authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		if (authorizedClient == null) {
			throw new IllegalArgumentException("Authorization not supported for " + this.clientRegistrationId);
		}
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		log.debug("Obtained access token");
		builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

}
