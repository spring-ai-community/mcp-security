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

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * A {@link ClientRegistrationRepository} tailored for MCP use-cases.
 *
 * @author Daniel Garnier-Moiroux
 */
public interface McpClientRegistrationRepository extends ClientRegistrationRepository {

	/**
	 * Register a client with the given MCP server. This discovers the MCP configuration,
	 * including resource identifier, supported scopes and associated authorization
	 * server.
	 * @param registrationId the Client's internal registration ID
	 * @param mcpServerUrl the URL of the server holding the metadata
	 * @param registrationRequest the base registration request to be used to specify
	 * parameters in the registration request
	 */
	void registerMcpClient(String registrationId, String mcpServerUrl,
			DynamicClientRegistrationRequest registrationRequest);

	/**
	 * Add an existing, pre-registered client to the repository.
	 * @param clientRegistration the client
	 * @param resourceId the MCP server's associated resource ID
	 */
	void addPreRegisteredClient(ClientRegistration clientRegistration, String resourceId);

	/**
	 * Find the associated resource identifier for the given registration.
	 * @param registrationId the registration ID
	 * @return the resource identifier
	 */
	@Nullable String findResourceIdByRegistrationId(String registrationId);

}
