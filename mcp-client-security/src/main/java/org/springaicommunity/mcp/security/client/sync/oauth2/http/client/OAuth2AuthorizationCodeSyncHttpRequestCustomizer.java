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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.common.OAuth2AuthorizationCodeAccessTokenResolver;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * An {@link McpSyncHttpClientRequestCustomizer} that adds an OAuth2 access token to
 * outgoing MCP client HTTP requests using the {@code authorization_code} grant type.
 * <p>
 * This customizer is intended for MCP client authorization scenarios where the client
 * acts on behalf of an authenticated end user. It retrieves an access token via the
 * {@link OAuth2AuthorizedClientManager} and attaches it as a {@code Bearer} token in the
 * {@code Authorization} header of each outgoing MCP request.
 * <p>
 * See {@link OAuth2AuthorizationCodeAccessTokenResolver} for behavior details.
 *
 * @author Daniel Garnier-Moiroux
 * @see OAuth2DcrSyncAuthorizationErrorHandler
 * @see OAuth2AuthorizationCodeAccessTokenResolver
 */
public class OAuth2AuthorizationCodeSyncHttpRequestCustomizer implements McpSyncHttpClientRequestCustomizer {

	private static final Logger log = LoggerFactory.getLogger(OAuth2AuthorizationCodeSyncHttpRequestCustomizer.class);

	private final OAuth2AuthorizationCodeAccessTokenResolver accessTokenResolver;

	public OAuth2AuthorizationCodeSyncHttpRequestCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, String clientRegistrationId) {
		this.accessTokenResolver = new OAuth2AuthorizationCodeAccessTokenResolver(authorizedClientManager,
				clientRegistrationRepository, clientRegistrationId);
	}

	@Override
	public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body,
			McpTransportContext context) {
		var accessToken = this.accessTokenResolver.resolve(context);
		if (accessToken == null) {
			return;
		}
		log.debug("Adding token to header");
		builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

	/**
	 * Fail when the client registration is missing. Set to {@code true} when using MCP
	 * client with pre-registered OAuth2 clients. Set to {@code false} when using with
	 * Dynamic Client Registration (DCR) or Client ID Metadata Document (CIMD)
	 * @param failOnMissingClientRegistration set to {@code false} for DCR or CIMD
	 * support. Defaults to {@code false}.
	 */
	public void failOnMissingClientRegistration(boolean failOnMissingClientRegistration) {
		this.accessTokenResolver.setFailOnMissingClientRegistration(failOnMissingClientRegistration);
	}

}
