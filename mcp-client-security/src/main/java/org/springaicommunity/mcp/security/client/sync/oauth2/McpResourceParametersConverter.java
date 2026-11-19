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

import org.springaicommunity.mcp.security.client.sync.oauth2.registration.McpClientRegistrationRepository;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Adds the RFC 8707 {@code resource} parameter, the MCP server's resource identifier, to
 * token requests. The identifier comes from the {@link McpClientRegistrationRepository},
 * where dynamic and CIMD registrations store it.
 * <p>
 * Add it to a token response client with
 * {@code addParametersConverter(new McpResourceParametersConverter<>(repository))}.
 *
 * @param <T> the type of grant request
 * @author Daniel Garnier-Moiroux
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8707">RFC 8707</a>
 */
public class McpResourceParametersConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, MultiValueMap<String, String>> {

	private final McpClientRegistrationRepository clientRegistrationRepository;

	public McpResourceParametersConverter(McpClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public MultiValueMap<String, String> convert(T grantRequest) {
		var parameters = new LinkedMultiValueMap<String, String>();
		var resource = this.clientRegistrationRepository
			.findResourceIdByRegistrationId(grantRequest.getClientRegistration().getRegistrationId());
		if (resource != null) {
			parameters.add("resource", resource);
		}
		return parameters;
	}

}
