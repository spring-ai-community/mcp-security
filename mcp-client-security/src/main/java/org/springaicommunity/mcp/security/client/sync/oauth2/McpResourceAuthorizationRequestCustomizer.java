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

package org.springaicommunity.mcp.security.client.sync.oauth2;

import java.util.function.Consumer;

import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

/**
 * Adds the RFC 8707 {@code resource} parameter, the MCP server's resource identifier, to
 * authorization requests. The identifier comes from the
 * {@link McpClientRegistrationRepository}, where dynamic and CIMD registrations store it.
 * No parameter is added when the registration has no resource identifier.
 * <p>
 * Set it on an authorization request resolver with
 * {@code resolver.setAuthorizationRequestCustomizer(new McpResourceAuthorizationRequestCustomizer(repository))}.
 *
 * @author Daniel Garnier-Moiroux
 * @see McpResourceParametersConverter
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8707">RFC 8707</a>
 */
public class McpResourceAuthorizationRequestCustomizer implements Consumer<OAuth2AuthorizationRequest.Builder> {

	private final McpClientRegistrationRepository clientRegistrationRepository;

	public McpResourceAuthorizationRequestCustomizer(McpClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public void accept(OAuth2AuthorizationRequest.Builder builder) {
		var registrationIdAttr = builder.build().getAttributes().get(OAuth2ParameterNames.REGISTRATION_ID);
		if (!(registrationIdAttr instanceof String registrationId)) {
			return;
		}
		var resource = this.clientRegistrationRepository.findResourceIdByRegistrationId(registrationId);
		if (resource != null) {
			builder.additionalParameters(params -> params.put("resource", resource));
		}
	}

}
