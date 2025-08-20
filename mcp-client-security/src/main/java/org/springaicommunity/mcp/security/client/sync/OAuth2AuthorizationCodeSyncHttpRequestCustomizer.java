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

package org.springaicommunity.mcp.security.client.sync;

import io.modelcontextprotocol.client.transport.SyncHttpRequestCustomizer;
import java.net.URI;
import java.net.http.HttpRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationCodeSyncHttpRequestCustomizer implements SyncHttpRequestCustomizer {

	private final OAuth2AuthorizedClientManager authorizedClientManager;

	private boolean failOnMissingServletRequest = true;

	private final String clientRegistrationId;

	public OAuth2AuthorizationCodeSyncHttpRequestCustomizer(OAuth2AuthorizedClientManager authorizedClientManager,
			String clientRegistrationId) {
		this.authorizedClientManager = authorizedClientManager;
		this.clientRegistrationId = clientRegistrationId;
	}

	public void setFailOnMissingServletRequest(boolean failOnMissingServletRequest) {
		this.failOnMissingServletRequest = failOnMissingServletRequest;
	}

	@Override
	public void customize(HttpRequest.Builder builder, String method, URI endpoint, String body) {
		if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes)) {
			if (!this.failOnMissingServletRequest) {
				return;
			}
			else {
				throw new IllegalStateException("Cannot use %s outside the context of an HttpServletRequest"
					.formatted(OAuth2AuthorizationCodeSyncHttpRequestCustomizer.class.getSimpleName()));

			}
		}

		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
			.withClientRegistrationId(this.clientRegistrationId)
			.principal(SecurityContextHolder.getContext().getAuthentication())
			.build();
		OAuth2AccessToken accessToken = this.authorizedClientManager.authorize(authorizeRequest).getAccessToken();
		builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue());
	}

}
