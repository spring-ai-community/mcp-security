/*
 * Copyright 2012-present the original author or authors.
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

package org.springaicommunity.mcp.security.authorizationserver.boot;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerProperties;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

/**
 * Maps {@link OAuth2AuthorizationServerProperties} to Authorization Server types.
 * <p>
 * Lifted from <a href=
 * "https://github.com/spring-projects/spring-boot/blob/main/module/spring-boot-security-oauth2-authorization-server/src/main/java/org/springframework/boot/security/oauth2/server/authorization/autoconfigure/servlet/OAuth2AuthorizationServerPropertiesMapper.java">
 * Spring Boot's OAuth2AuthorizationServerPropertiesMapper.</a>
 *
 * @author Steve Riesenberg
 * @author Florian Lemaire
 */

final class OAuth2AuthorizationServerPropertiesMapper {

	private final OAuth2AuthorizationServerProperties properties;

	OAuth2AuthorizationServerPropertiesMapper(OAuth2AuthorizationServerProperties properties) {
		this.properties = properties;
	}

	List<RegisteredClient> asRegisteredClients() {
		List<RegisteredClient> registeredClients = new ArrayList<>();
		this.properties.getClient()
			.forEach((registrationId, client) -> registeredClients.add(getRegisteredClient(registrationId, client)));
		return registeredClients;
	}

	private RegisteredClient getRegisteredClient(String registrationId,
			OAuth2AuthorizationServerProperties.Client client) {
		OAuth2AuthorizationServerProperties.Registration registration = client.getRegistration();
		PropertyMapper map = PropertyMapper.get();
		RegisteredClient.Builder builder = RegisteredClient.withId(registrationId);
		map.from(registration::getClientId).to(builder::clientId);
		map.from(registration::getClientSecret).to(builder::clientSecret);
		map.from(registration::getClientName).to(builder::clientName);
		registration.getClientAuthenticationMethods()
			.forEach((clientAuthenticationMethod) -> map.from(clientAuthenticationMethod)
				.as(ClientAuthenticationMethod::new)
				.to(builder::clientAuthenticationMethod));
		registration.getAuthorizationGrantTypes()
			.forEach((authorizationGrantType) -> map.from(authorizationGrantType)
				.as(AuthorizationGrantType::new)
				.to(builder::authorizationGrantType));
		registration.getRedirectUris().forEach((redirectUri) -> map.from(redirectUri).to(builder::redirectUri));
		registration.getPostLogoutRedirectUris()
			.forEach((redirectUri) -> map.from(redirectUri).to(builder::postLogoutRedirectUri));
		registration.getScopes().forEach((scope) -> map.from(scope).to(builder::scope));
		builder.clientSettings(getClientSettings(client, map));
		builder.tokenSettings(getTokenSettings(client, map));
		return builder.build();
	}

	private ClientSettings getClientSettings(OAuth2AuthorizationServerProperties.Client client, PropertyMapper map) {
		ClientSettings.Builder builder = ClientSettings.builder();
		map.from(client::isRequireProofKey).to(builder::requireProofKey);
		map.from(client::isRequireAuthorizationConsent).to(builder::requireAuthorizationConsent);
		map.from(client::getJwkSetUri).to(builder::jwkSetUrl);
		map.from(client::getTokenEndpointAuthenticationSigningAlgorithm)
			.as(this::jwsAlgorithm)
			.to(builder::tokenEndpointAuthenticationSigningAlgorithm);
		return builder.build();
	}

	private TokenSettings getTokenSettings(OAuth2AuthorizationServerProperties.Client client, PropertyMapper map) {
		OAuth2AuthorizationServerProperties.Token token = client.getToken();
		TokenSettings.Builder builder = TokenSettings.builder();
		map.from(token::getAuthorizationCodeTimeToLive).to(builder::authorizationCodeTimeToLive);
		map.from(token::getAccessTokenTimeToLive).to(builder::accessTokenTimeToLive);
		map.from(token::getAccessTokenFormat).as(OAuth2TokenFormat::new).to(builder::accessTokenFormat);
		map.from(token::getDeviceCodeTimeToLive).to(builder::deviceCodeTimeToLive);
		map.from(token::isReuseRefreshTokens).to(builder::reuseRefreshTokens);
		map.from(token::getRefreshTokenTimeToLive).to(builder::refreshTokenTimeToLive);
		map.from(token::getIdTokenSignatureAlgorithm)
			.as(this::signatureAlgorithm)
			.to(builder::idTokenSignatureAlgorithm);
		return builder.build();
	}

	private JwsAlgorithm jwsAlgorithm(String signingAlgorithm) {
		String name = signingAlgorithm.toUpperCase(Locale.ROOT);
		JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.from(name);
		if (jwsAlgorithm == null) {
			jwsAlgorithm = MacAlgorithm.from(name);
		}
		return jwsAlgorithm;
	}

	private SignatureAlgorithm signatureAlgorithm(String signatureAlgorithm) {
		return SignatureAlgorithm.from(signatureAlgorithm.toUpperCase(Locale.ROOT));
	}

}