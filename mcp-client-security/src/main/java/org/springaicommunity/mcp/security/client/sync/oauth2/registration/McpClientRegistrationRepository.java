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

import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * A {@link ClientRegistrationRepository} tailored for MCP use-cases, providing storage
 * for {@link ClientRegistration}s and their associated resource identifiers.
 * <p>
 * In this model, clients are considered to be mutable. The most common use-case is the
 * "scope step up" flow, where the server requests minimal scopes for each request,
 * leading to having to update the registration's scopes depending on server responses.
 *
 * @author Daniel Garnier-Moiroux
 * @see <a
 * href="https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#scope-selection-strategy>Scope
 * Selection Strategy</a>
 */
public interface McpClientRegistrationRepository extends ClientRegistrationRepository {

	/**
	 * Add a client registration to the repository, along with the associated Resource ID
	 * from the upstream MCP server.
	 * <p>
	 * This is a workaround until the information can be stored in the
	 * {@link ClientRegistration.ClientSettings} object.
	 *
	 * @see <a href=
	 * "https://github.com/spring-projects/spring-security/issues/18863">Store arbitrary
	 * information in ClientRegistration.ClientSettings (#18863)</a>
	 * @param clientRegistration the client
	 * @param resourceId the MCP server's associated resource ID
	 */
	void addClientRegistration(ClientRegistration clientRegistration, @Nullable String resourceId);

	/**
	 * Update an existing {@link ClientRegistration} if it exists. Otherwise, this method
	 * is a no-op.
	 * @param registrationId The ID of the registration to update.
	 * @param clientRegistrationConsumer A consumer of {@link ClientRegistration.Builder}
	 * to update the client registration.
	 */
	void updateClientRegistration(String registrationId,
			Consumer<ClientRegistration.Builder> clientRegistrationConsumer);

	/**
	 * Find the associated resource identifier for the given registration.
	 * <p>
	 * This is a workaround until the information can be stored in the
	 * {@link ClientRegistration.ClientSettings} object.
	 *
	 * @see <a href=
	 * "https://github.com/spring-projects/spring-security/issues/18863">Store arbitrary
	 * information in ClientRegistration.ClientSettings (#18863)</a>
	 * @param registrationId the registration ID for a given client
	 * @return the resource identifier linked to that particular client, null if there is
	 * no client, and null if a client exists but does not have an associated resource ID.
	 */
	@Nullable String findResourceIdByRegistrationId(String registrationId);

}
