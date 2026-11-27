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

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.util.Assert;

/**
 * An {@link McpOAuth2ClientManager} that tries several managers in order, until one
 * supports the authorization server.
 * <p>
 * The MCP authorization requires trying CIMD then DCR, in that order.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-registration-approaches">MCP
 * Authorization: client registration approaches</a>
 */
public class DelegatingMcpOAuth2ClientManager implements McpOAuth2ClientManager {

	private static final Logger log = LoggerFactory.getLogger(DelegatingMcpOAuth2ClientManager.class);

	private final List<McpOAuth2ClientManager> delegates;

	public DelegatingMcpOAuth2ClientManager(McpOAuth2ClientManager... delegates) {
		this(List.of(delegates));
	}

	public DelegatingMcpOAuth2ClientManager(List<McpOAuth2ClientManager> delegates) {
		Assert.notEmpty(delegates, "delegates cannot be empty");
		Assert.noNullElements(delegates, "delegates cannot contain null elements");
		this.delegates = List.copyOf(delegates);
	}

	/**
	 * Obtain a client with the first manager that supports the authorization server.
	 * @throws ClientAlreadyExistsException as soon as a manager finds an existing client
	 * @throws ClientRegistrationNotSupportedException the exception of the last manager
	 * when no manager supports the authorization server, with those of the other managers
	 * as suppressed exceptions
	 */
	@Override
	public void registerClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader, String baseUrl)
			throws ClientAlreadyExistsException, ClientRegistrationNotSupportedException {
		var notSupported = new ArrayList<ClientRegistrationNotSupportedException>();
		for (var delegate : this.delegates) {
			try {
				delegate.registerClient(registrationId, mcpServerUrl, wwwAuthenticateHeader, baseUrl);
				return;
			}
			catch (ClientRegistrationNotSupportedException ex) {
				log.debug("Client [{}] not registered: {}", registrationId, ex.getMessage());
				notSupported.add(ex);
			}
		}
		var last = notSupported.remove(notSupported.size() - 1);
		notSupported.forEach(last::addSuppressed);
		throw last;
	}

	/**
	 * Update the scopes with the first manager that updates them.
	 */
	@Override
	public boolean updateScopes(String registrationId, String wwwAuthenticateHeader) {
		for (var delegate : this.delegates) {
			if (delegate.updateScopes(registrationId, wwwAuthenticateHeader)) {
				return true;
			}
		}
		return false;
	}

}
