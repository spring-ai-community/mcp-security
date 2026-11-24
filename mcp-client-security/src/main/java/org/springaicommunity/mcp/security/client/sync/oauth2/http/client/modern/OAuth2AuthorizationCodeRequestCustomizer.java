/*
 * Copyright 2026-2026 the original author or authors.
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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client.modern;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequest;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequestCustomizer;
import io.modelcontextprotocol.modern.client.transport.McpHttpRequestHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.common.OAuth2AuthorizationCodeAccessTokenResolver;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * An {@link McpHttpRequestCustomizer.Sync} that adds an OAuth2 access token to outgoing
 * MCP client HTTP requests using the {@code authorization_code} grant type.
 * <p>
 * This customizer is intended for MCP client authorization scenarios where the client
 * acts on behalf of an authenticated end user. It retrieves an access token via the
 * {@link OAuth2AuthorizedClientManager} and attaches it as a {@code Bearer} token in the
 * {@code Authorization} header of each outgoing MCP request.
 *
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationCodeRequestCustomizer implements McpHttpRequestCustomizer.Sync {

	private static final Logger log = LoggerFactory.getLogger(OAuth2AuthorizationCodeRequestCustomizer.class);

	private final OAuth2AuthorizationCodeAccessTokenResolver accessTokenResolver;

	public OAuth2AuthorizationCodeRequestCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			ClientRegistrationRepository clientRegistrationRepository, String clientRegistrationId) {
		this.accessTokenResolver = new OAuth2AuthorizationCodeAccessTokenResolver(authorizedClientManager,
				clientRegistrationRepository, clientRegistrationId);
	}

	@Override
	public void customize(McpHttpRequest request, McpHttpRequestHeaders headers, McpTransportContext context) {
		var accessToken = this.accessTokenResolver.resolve(context);
		if (accessToken == null) {
			log.debug("No token for {}", request);
			return;
		}
		headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

	/**
	 * Fail when the client registration is missing. Set to {@code true} for
	 * pre-registered clients, leave {@code false} for Dynamic Client Registration (DCR)
	 * or Client ID Metadata Documents (CIMD).
	 * @param failOnMissingClientRegistration defaults to {@code false}
	 */
	public void setFailOnMissingClientRegistration(boolean failOnMissingClientRegistration) {
		this.accessTokenResolver.setFailOnMissingClientRegistration(failOnMissingClientRegistration);
	}

}
