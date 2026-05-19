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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.client.metadata;

import java.util.Set;

import org.springaicommunity.mcp.security.common.url.DefaultUrlValidator;
import org.springaicommunity.mcp.security.common.url.InvalidUrlException;
import org.springaicommunity.mcp.security.common.url.UrlValidator;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Default implementation for {@link ClientMetadataValidator}.
 *
 * @author Daniel Garnier-Moiroux
 */
public class DefaultClientMetadataValidator implements ClientMetadataValidator {

	private static final Set<String> ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS = Set.of(
			ClientAuthenticationMethod.NONE.getValue(), ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
			ClientAuthenticationMethod.TLS_CLIENT_AUTH.getValue(),
			ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue());

	private final UrlValidator urlValidator;

	public DefaultClientMetadataValidator() {
		this(new DefaultUrlValidator());
	}

	public DefaultClientMetadataValidator(UrlValidator urlValidator) {
		this.urlValidator = urlValidator;
	}

	@Override
	public void validate(String clientIdUrl, OAuth2ClientRegistration metadata) throws InvalidClientMetadataException {
		String clientId = metadata.getClientId();
		if (!StringUtils.hasText(clientId)) {
			throw new InvalidClientMetadataException(clientIdUrl, OAuth2ParameterNames.CLIENT_ID);
		}
		if (!clientIdUrl.equals(clientId)) {
			throw new InvalidClientMetadataException(
					"Invalid client metadata: client_id from metadata [%s] does not match clientId from request [%s]"
						.formatted(clientId, clientIdUrl),
					clientIdUrl, OAuth2ParameterNames.CLIENT_ID);
		}
		if (StringUtils.hasText(metadata.getClientSecret())) {
			throw new InvalidClientMetadataException(clientIdUrl, OAuth2ParameterNames.CLIENT_SECRET);
		}
		if (metadata.getClientSecretExpiresAt() != null) {
			throw new InvalidClientMetadataException(clientIdUrl,
					OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
		}
		if (CollectionUtils.isEmpty(metadata.getRedirectUris())) {
			throw new InvalidClientMetadataException(clientIdUrl, OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
		}
		for (String r : metadata.getRedirectUris()) {
			try {
				this.urlValidator.validateUrl(r);
			}
			catch (InvalidUrlException e) {
				throw new InvalidClientMetadataException(clientIdUrl, OAuth2ClientMetadataClaimNames.REDIRECT_URIS, e);
			}
		}
		String tokenEndpointAuthenticationMethod = metadata.getTokenEndpointAuthenticationMethod();
		if (StringUtils.hasText(tokenEndpointAuthenticationMethod)
				&& !ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS.contains(tokenEndpointAuthenticationMethod)) {
			throw new InvalidClientMetadataException(clientIdUrl,
					OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD);
		}
	}

}
