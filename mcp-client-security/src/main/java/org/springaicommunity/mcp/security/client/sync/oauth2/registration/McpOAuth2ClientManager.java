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

/**
 * Create and manage OAuth2 clients: "creates" a client for an MCP server just in time, on
 * its first {@code 401}, and "steps up" its scopes on an {@code insufficient_scope}
 * {@code 403}.
 * <p>
 * Implementations support either Client ID Metadata Document (CIMD) or Dynamic Client
 * Registration (DCR).
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#client-registration-approaches">MCP
 * Authorization: client registration approaches</a>
 */
public interface McpOAuth2ClientManager {

	/**
	 * Obtain an OAuth2 client for the given MCP server, discovering the authorization
	 * server from the {@code WWW-Authenticate} header of a {@code 401} response.
	 * @param registrationId the unique identifier for this client registration
	 * @param mcpServerUrl the URL of the MCP server
	 * @param wwwAuthenticateHeader the {@code WWW-Authenticate} header from the
	 * {@code 401} response
	 * @param baseUrl the base URL of the running application, used to build the redirect
	 * URI, and the {@code client_id} for Client ID Metadata Documents
	 * @throws ClientAlreadyExistsException when a client with this registration ID exists
	 * already
	 * @throws ClientRegistrationNotSupportedException when the authorization server does
	 * not support this way of obtaining a client
	 */
	void registerClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader, String baseUrl)
			throws ClientAlreadyExistsException, ClientRegistrationNotSupportedException;

	/**
	 * Update an existing client registration's scopes based on an
	 * {@code insufficient_scope} error in the {@code WWW-Authenticate} header.
	 * <p>
	 * Used to "step up" the required scopes.
	 *
	 * @see <a href=
	 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#scope-challenge-handling">Scope
	 * challenge handling</a>
	 * @param registrationId the unique identifier for the client registration to update
	 * @param wwwAuthenticateHeader the {@code WWW-Authenticate} header from a prior
	 * {@code 403} response, containing the required scopes
	 * @return {@code true} if the scopes were updated, {@code false} otherwise
	 */
	boolean updateScopes(String registrationId, String wwwAuthenticateHeader);

}
