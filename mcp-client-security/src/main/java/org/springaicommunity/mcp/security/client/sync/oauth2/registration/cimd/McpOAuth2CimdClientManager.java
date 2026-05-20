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
package org.springaicommunity.mcp.security.client.sync.oauth2.registration.cimd;

/**
 * An OAuth2 client manager to register and update CIMD-based OAuth2 clients for MCP.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP
 * Specification: authorization</a>
 * @see <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/">OAuth
 * 2.0 Client ID Metadata Document</a>
 */

public interface McpOAuth2CimdClientManager {

	/**
	 * Create an OAuth2 client responding to an HTTP 401 response from an MCP server. The
	 * base URL is used to create the client ID url.
	 * <p>
	 * The {@code client_id} URL will be in the form
	 * {baseUrl}/{registrationId}/client-id-metadata.json
	 * @param registrationId the ID of the registration
	 * @param mcpServerUrl the URL of the MCP server this client is used for
	 * @param wwwAuthenticateHeader the WWW-Authenticate header from the MCP server
	 * response
	 * @param baseUrl the base URL of the running application
	 * @throws ClientAlreadyExistsException When creating a client that already exists.
	 */
	void createClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader, String baseUrl)
			throws ClientAlreadyExistsException;

	/**
	 * Update an existing OAuth2 client based on an HTTP 403 response from an MCP server.
	 * Typically used in scope step up flows.
	 * @param registrationId the ID of the registration
	 * @param wwwAuthenticateHeader the WWW-Authenticate header from the MCP server
	 * response
	 * @return true if the client was updated, false otherwise.
	 */
	boolean updateClient(String registrationId, String wwwAuthenticateHeader);

}
