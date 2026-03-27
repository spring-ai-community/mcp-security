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

package org.springaicommunity.mcp.security.client.sync.oauth2.registration;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springaicommunity.mcp.security.client.sync.oauth2.metadata.WwwAuthenticateParameters;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INSUFFICIENT_SCOPE;

/**
 * Partial implementation of {@link McpOAuth2ClientManager} that does not support dynamic
 * client registration. Delegates storage to a {@link McpClientRegistrationRepository}.
 * For full DCR support, see {@link DefaultMcpOAuth2ClientManager}.
 * <p>
 * Other methods throw when called.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP -
 * Authorization</a>
 */
public class ScopeStepUpMcpOAuth2ClientManager implements McpOAuth2ClientManager {

	private static final Logger log = LoggerFactory.getLogger(ScopeStepUpMcpOAuth2ClientManager.class);

	protected final McpClientRegistrationRepository repository;

	public ScopeStepUpMcpOAuth2ClientManager(McpClientRegistrationRepository repository) {
		this.repository = repository;
	}

	@Override
	public void registerMcpClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest dynamicClientRegistrationRequest) {
		throw new IllegalStateException("Dynamic client registration is not supported");
	}

	@Override
	public void registerMcpClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader,
			DynamicClientRegistrationRequest dynamicClientRegistrationRequest) {
		throw new IllegalStateException("Dynamic client registration is not supported");
	}

	@Override
	public boolean updateMcpClient(String registrationId, String wwwAuthenticateHeader) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(wwwAuthenticateHeader, "wwwAuthenticateHeader cannot be empty");
		var authenticateParameters = WwwAuthenticateParameters.parse(wwwAuthenticateHeader);
		if (authenticateParameters == null) {
			log.debug("Could not parse WWW-Authenticate header [{}] for registration [{}]", wwwAuthenticateHeader,
					registrationId);
			return false;
		}
		if (!INSUFFICIENT_SCOPE.equals(authenticateParameters.getError())) {
			log.debug("WWW-Authenticate error is [{}], not insufficient_scope, skipping update for registration [{}]",
					authenticateParameters.getError(), registrationId);
			return false;
		}
		if (!StringUtils.hasText(authenticateParameters.getScope())) {
			log.debug("No scope in WWW-Authenticate header for registration [{}]", registrationId);
			return false;
		}
		var scopes = authenticateParameters.getScope().split(" ");
		if (scopes.length == 0) {
			log.debug("No scope in WWW-Authenticate header for registration [{}]", registrationId);
			return false;
		}

		log.debug("Attempting scope step-up for registration [{}] with scopes {}", registrationId,
				Arrays.asList(scopes));
		AtomicBoolean result = new AtomicBoolean(false);
		this.repository.updateClientRegistration(registrationId, builder -> {
			var existingClient = builder.build();
			if (existingClient.getScopes() == null || !existingClient.getScopes().containsAll(Arrays.asList(scopes))) {
				Set<String> merged = new LinkedHashSet<>();
				if (existingClient.getScopes() != null) {
					merged.addAll(existingClient.getScopes());
				}
				merged.addAll(Arrays.asList(scopes));
				log.debug("Updating scopes for registration [{}]: {} -> {}", registrationId, existingClient.getScopes(),
						merged);
				builder.scope(merged.toArray(String[]::new));
				result.set(true);
			}
			else {
				log.debug("Scopes for registration [{}] already contain required scopes {}", registrationId,
						Arrays.asList(scopes));
			}
		});

		return result.get();
	}

}
