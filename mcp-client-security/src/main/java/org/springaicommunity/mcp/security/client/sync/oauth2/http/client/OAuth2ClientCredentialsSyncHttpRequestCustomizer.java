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
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.common.OAuth2ClientCredentialsAccessTokenResolver;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;

/**
 * Adds an OAuth2 access token to outgoing MCP client HTTP requests using the
 * {@code client_credentials} grant type.
 * <p>
 * This customizer is intended for machine-to-machine (M2M) scenarios where the MCP client
 * acts on its own behalf, without a user context. It uses an
 * {@link AuthorizedClientServiceOAuth2AuthorizedClientManager} to obtain and cache access
 * tokens independently of any incoming HTTP request or user authentication.
 * <p>
 * Scope step-up is not supported in this flow: since there is no user interaction, the
 * MCP client must request all necessary scopes upfront when obtaining the token.
 * <p>
 * The resolved access token is added as a {@code Bearer} token in the
 * {@code Authorization} header of each outgoing MCP request.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2ClientCredentialsSyncHttpRequestCustomizer implements McpSyncHttpClientRequestCustomizer {

	private final OAuth2ClientCredentialsAccessTokenResolver accessTokenResolver;

	public OAuth2ClientCredentialsSyncHttpRequestCustomizer(
			AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager, String clientRegistrationId) {
		this.accessTokenResolver = new OAuth2ClientCredentialsAccessTokenResolver(authorizedClientManager,
				clientRegistrationId);
	}

	@Override
	public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body,
			McpTransportContext context) {
		var accessToken = this.accessTokenResolver.resolve();
		builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

}
