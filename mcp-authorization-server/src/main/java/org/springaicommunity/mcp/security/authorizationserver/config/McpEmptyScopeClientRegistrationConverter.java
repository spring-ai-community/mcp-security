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

package org.springaicommunity.mcp.security.authorizationserver.config;

import java.net.URL;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2ClientRegistrationHttpMessageConverter;
import org.springframework.util.StringUtils;

/**
 * Converts dynamic client registration parameters into an
 * {@link OAuth2ClientRegistration}, ignoring an empty {@code scope} parameter, e.g.
 * {@code "scope": ""}. OAuth2 specifies that the "scope" claim should have at least 1
 * character, but some clients, including the MCP Inspector 2.7.0, sends an empty scope
 * string.
 * <p>
 * It is lifted from
 * {@code OAuth2ClientRegistrationHttpMessageConverter.MapOAuth2ClientRegistrationConverter}.
 * <p>
 * For internal use only.
 *
 * @author Daniel Garnier-Moiroux
 * @see OAuth2ClientRegistrationHttpMessageConverter
 * @see <a href="https://github.com/spring-projects/spring-security/pull/19765">Spring
 * Security #19765</a>
 */
class McpEmptyScopeClientRegistrationConverter implements Converter<Map<String, Object>, OAuth2ClientRegistration> {

	private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService.getSharedInstance();

	private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

	private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);

	private static final TypeDescriptor INSTANT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Instant.class);

	private static final TypeDescriptor URL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(URL.class);

	private static final Converter<Object, ?> INSTANT_CONVERTER = getConverter(INSTANT_TYPE_DESCRIPTOR);

	private final ClaimTypeConverter claimTypeConverter;

	@SuppressWarnings("NullAway")
	McpEmptyScopeClientRegistrationConverter() {
		Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
		Converter<Object, ?> collectionStringConverter = getConverter(
				TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
		Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

		Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
		claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_ID, stringConverter);
		claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, INSTANT_CONVERTER);
		claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET, stringConverter);
		claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT,
				McpEmptyScopeClientRegistrationConverter::convertClientSecretExpiresAt);
		claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_NAME, stringConverter);
		claimConverters.put(OAuth2ClientMetadataClaimNames.REDIRECT_URIS, collectionStringConverter);
		claimConverters.put(OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, stringConverter);
		claimConverters.put(OAuth2ClientMetadataClaimNames.GRANT_TYPES, collectionStringConverter);
		claimConverters.put(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, collectionStringConverter);
		claimConverters.put(OAuth2ClientMetadataClaimNames.SCOPE,
				McpEmptyScopeClientRegistrationConverter::convertScope);
		claimConverters.put(OAuth2ClientMetadataClaimNames.JWKS_URI, urlConverter);
		this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
	}

	@Override
	public OAuth2ClientRegistration convert(Map<String, Object> source) {
		Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
		Object clientSecretExpiresAt = parsedClaims.get(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
		if (clientSecretExpiresAt instanceof Number && clientSecretExpiresAt.equals(0)) {
			parsedClaims.remove(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
		}
		// Update matching https://github.com/spring-projects/spring-security/pull/19765
		Object scope = parsedClaims.get(OAuth2ClientMetadataClaimNames.SCOPE);
		if (scope instanceof Collection<?> scopes && scopes.isEmpty()) {
			parsedClaims.remove(OAuth2ClientMetadataClaimNames.SCOPE);
		}
		return OAuth2ClientRegistration.withClaims(parsedClaims).build();
	}

	@SuppressWarnings("NullAway")
	private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
		return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
	}

	private static @Nullable Instant convertClientSecretExpiresAt(Object clientSecretExpiresAt) {
		if (clientSecretExpiresAt != null && String.valueOf(clientSecretExpiresAt).equals("0")) {
			// 0 indicates that client_secret_expires_at does not expire
			return null;
		}
		return (Instant) INSTANT_CONVERTER.convert(clientSecretExpiresAt);
	}

	private static List<String> convertScope(@Nullable Object scope) {
		if (scope == null) {
			return List.of();
		}
		return List.of(StringUtils.delimitedListToStringArray(scope.toString(), " "));
	}

}
