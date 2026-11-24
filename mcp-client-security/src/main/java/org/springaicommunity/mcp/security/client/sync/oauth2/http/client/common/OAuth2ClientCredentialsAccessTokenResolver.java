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

package org.springaicommunity.mcp.security.client.sync.oauth2.http.client.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.Assert;

/**
 * FOR INTERNAL USE ONLY.
 * <p>
 * Resolves the MCP client's own OAuth2 access token, obtained with the
 * {@code client_credentials} grant.
 * <p>
 * Internal class used by both the legacy and the modern transport. The client acts on its
 * own behalf, without a user context, so the token is stored and looked up under a fixed
 * principal name, {@value #PRINCIPAL_NAME}. It uses an
 * {@link AuthorizedClientServiceOAuth2AuthorizedClientManager}, which needs no servlet
 * request and reuses the token until it expires.
 * <p>
 * Scope step-up is not supported: since there is no user interaction, the MCP client must
 * request all necessary scopes upfront when obtaining the token.
 *
 * @author Daniel Garnier-Moiroux
 */
public final class OAuth2ClientCredentialsAccessTokenResolver {

	/**
	 * The principal name under which tokens are stored.
	 */
	static final String PRINCIPAL_NAME = "mcp-client-service";

	private static final Logger log = LoggerFactory.getLogger(OAuth2ClientCredentialsAccessTokenResolver.class);

	private final AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager;

	private final String clientRegistrationId;

	public OAuth2ClientCredentialsAccessTokenResolver(
			AuthorizedClientServiceOAuth2AuthorizedClientManager authorizedClientManager, String clientRegistrationId) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationId = clientRegistrationId;
	}

	/**
	 * Resolve the client's access token.
	 * @return the access token
	 * @throws IllegalArgumentException when the manager does not support authorizing the
	 * client
	 */
	public OAuth2AccessToken resolve() {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(this.clientRegistrationId)
			.principal(PRINCIPAL_NAME)
			.build();
		log.debug("Requesting access token");
		var authorizedClient = this.authorizedClientManager.authorize(authorizeRequest);
		if (authorizedClient == null) {
			throw new IllegalArgumentException("Authorization not supported for " + this.clientRegistrationId);
		}
		log.debug("Obtained access token");
		return authorizedClient.getAccessToken();
	}

}
