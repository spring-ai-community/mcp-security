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
 * Manages OAuth2 client registrations for MCP servers, handling dynamic client
 * registration and scope updates as part of the MCP Authorization flow.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a href=
 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization">MCP
 * Authorization</a>
 */
public interface McpOAuth2ClientManager {

	/**
	 * Register an OAuth2 client for the given MCP server, discovering the authorization
	 * server by calling the MCP server's resource metadata endpoint.
	 * <p>
	 * Used to register clients ahead of time, before calling an MCP server.
	 * @param registrationId the unique identifier for this client registration
	 * @param mcpServerUrl the URL of the MCP server
	 * @param dynamicClientRegistrationRequest the request parameters for OAuth2 dynamic
	 * client registration
	 */
	void registerMcpClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest dynamicClientRegistrationRequest);

	/**
	 * Register an OAuth2 client for the given MCP server, using a previously obtained
	 * {@code WWW-Authenticate} header to discover the authorization server.
	 * <p>
	 * Used to dynamically register clients just in time, based on an MCP server response.
	 *
	 * @see <a href=
	 * "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#dynamic-client-registration">Dynamic
	 * client registration</a>
	 * @param registrationId the unique identifier for this client registration
	 * @param mcpServerUrl the URL of the MCP server
	 * @param wwwAuthenticateHeader the {@code WWW-Authenticate} header from a prior 401
	 * response
	 * @param dynamicClientRegistrationRequest the request parameters for OAuth2 dynamic
	 * client registration
	 */
	void registerMcpClient(String registrationId, String mcpServerUrl, String wwwAuthenticateHeader,
			DynamicClientRegistrationRequest dynamicClientRegistrationRequest);

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
	 * @param wwwAuthenticateHeader the {@code WWW-Authenticate} header from a prior 403
	 * response, containing the required scopes
	 * @return {@code true} if the scopes were updated, {@code false} otherwise
	 */
	boolean updateMcpClient(String registrationId, String wwwAuthenticateHeader);

}
