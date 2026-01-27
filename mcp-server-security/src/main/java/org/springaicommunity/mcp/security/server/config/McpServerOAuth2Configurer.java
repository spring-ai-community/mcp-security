/*
 * Copyright 2025-2026 the original author or authors.
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

package org.springaicommunity.mcp.security.server.config;

import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.oauth2.authentication.BearerResourceMetadataTokenAuthenticationEntryPoint;
import org.springaicommunity.mcp.security.server.oauth2.jwt.AudienceValidationJwtDecoder;
import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.util.Assert;

/**
 * @author Daniel Garnier-Moiroux
 */
public class McpServerOAuth2Configurer extends AbstractHttpConfigurer<McpServerOAuth2Configurer, HttpSecurity> {

	@Nullable
	private String issuerUri = null;

	private String resourceName = "Spring MCP Resource Server";

	@Nullable
	private Consumer<OAuth2ProtectedResourceMetadata.Builder> customizer = null;

	private ResourceIdentifier resourceIdentifier = new ResourceIdentifier("/mcp");

	private boolean validateAudienceClaim = false;

	private Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer = Customizer
		.withDefaults();

	@Nullable
	private JwtDecoder jwtDecoder;

	public McpServerOAuth2Configurer authorizationServer(String issuerUri) {
		this.issuerUri = issuerUri;
		return this;
	}

	public McpServerOAuth2Configurer resourceName(String resourceName) {
		this.resourceName = resourceName;
		return this;
	}

	public McpServerOAuth2Configurer resourcePath(String resourceIdentifier) {
		this.resourceIdentifier = new ResourceIdentifier(resourceIdentifier);
		return this;
	}

	public McpServerOAuth2Configurer protectedResourceMetadataCustomizer(
			Consumer<OAuth2ProtectedResourceMetadata.Builder> customizer) {
		Assert.notNull(customizer, "customizer cannot be null");
		this.customizer = customizer;
		return this;
	}

	public McpServerOAuth2Configurer validateAudienceClaim(boolean validateAudienceClaim) {
		this.validateAudienceClaim = validateAudienceClaim;
		return this;
	}

	public McpServerOAuth2Configurer jwtDecoder(JwtDecoder jwtDecoder) {
		this.jwtDecoder = jwtDecoder;
		return this;
	}

	/**
	 * Customize the underlying Spring Security OAuth2 Resource Server configuration,
	 * through a {@link OAuth2ResourceServerConfigurer}.
	 * @param oauth2ResourceServerCustomizer a customizer of OAuth2 Resource Server.
	 * Defaults to a no-op {@link Customizer#withDefaults()}.
	 * @return The {@link McpServerOAuth2Configurer} for further configuration.
	 */
	public McpServerOAuth2Configurer oauth2ResourceServer(
			Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer) {
		Assert.notNull(oauth2ResourceServerCustomizer, "oauth2ResourceServerCustomizer cannot be null");
		this.oauth2ResourceServerCustomizer = oauth2ResourceServerCustomizer;
		return this;
	}

	@Override
	public void init(HttpSecurity http) {
		Assert.notNull(this.issuerUri, "authorizationServer cannot be null");
		Assert.notNull(this.resourceIdentifier, "resourceIdentifier cannot be null");

		var entryPoint = new BearerResourceMetadataTokenAuthenticationEntryPoint(this.resourceIdentifier);

		http.oauth2ResourceServer(resourceServer -> {
			resourceServer.jwt(jwt -> jwt.decoder(getJwtDecoder(this.issuerUri)));
			resourceServer.authenticationEntryPoint(entryPoint);
			resourceServer.protectedResourceMetadata(protectedResource -> protectedResource
				.protectedResourceMetadataCustomizer(getProtectedMetadataCustomizer(this.issuerUri)));
			this.oauth2ResourceServerCustomizer.customize(resourceServer);
		});
	}

	private JwtDecoder getJwtDecoder(String issuerUri) {
		var rawDecoder = this.jwtDecoder != null ? this.jwtDecoder
				: NimbusJwtDecoder.withIssuerLocation(issuerUri).build();

		if (this.validateAudienceClaim) {
			return new AudienceValidationJwtDecoder(rawDecoder, this.resourceIdentifier);
		}

		return rawDecoder;
	}

	private Consumer<OAuth2ProtectedResourceMetadata.Builder> getProtectedMetadataCustomizer(String issuerUri) {
		if (this.customizer != null) {
			return this.customizer;
		}
		return (protectedMetadata) -> protectedMetadata.authorizationServer(issuerUri).resourceName(this.resourceName);
	}

	public static McpServerOAuth2Configurer mcpServerOAuth2() {
		return new McpServerOAuth2Configurer();
	}

}
