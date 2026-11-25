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

import org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd.CimdMcpOAuth2ClientManager;

/**
 * Partial implementation of {@link McpOAuth2ClientManager} that only steps up scopes, and
 * does not register clients. Delegates storage to a
 * {@link McpClientRegistrationRepository}. For full support, see either
 * {@link DcrMcpOAuth2ClientManager} or {@link CimdMcpOAuth2ClientManager}.
 * <p>
 * {@link #registerClient(String, String, String, String)} throws when called.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP -
 * Authorization</a>
 */
public class ScopeStepUpMcpOAuth2ClientManager implements McpOAuth2ClientManager {

	protected final McpClientRegistrationRepository repository;

	private final ScopeStepUp scopeStepUp;

	public ScopeStepUpMcpOAuth2ClientManager(McpClientRegistrationRepository repository) {
		this.repository = repository;
		this.scopeStepUp = new ScopeStepUp(repository);
	}

	@Override
	public void registerClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader,
			String baseUrl) {
		throw new IllegalStateException("Client registration is not supported");
	}

	@Override
	public boolean updateScopes(String registrationId, String wwwAuthenticateHeader) {
		return this.scopeStepUp.updateOAuth2ClientScopes(registrationId, wwwAuthenticateHeader);
	}

}
