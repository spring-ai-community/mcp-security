/*
 * Copyright 2025-2025 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import org.springaicommunity.mcp.security.server.oauth2.authentication.BearerResourceMetadataTokenAuthenticationEntryPoint;
import org.springaicommunity.mcp.security.server.oauth2.jwt.JwtResourceValidator;
import org.springaicommunity.mcp.security.server.oauth2.metadata.OAuth2ProtectedResourceMetadata;
import org.springaicommunity.mcp.security.server.oauth2.metadata.OAuth2ProtectedResourceMetadataEndpointFilter;
import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.Assert;

/**
 * @author Daniel Garnier-Moiroux
 */
public class McpServerOAuth2Configurer extends AbstractHttpConfigurer<McpServerOAuth2Configurer, HttpSecurity> {

	private String issuerUri = null;

	private final List<String> scopes = new ArrayList<>();

	private String bearerMethod = "header";

	private String resourceName = "Spring MCP Resource Server";

	private Consumer<OAuth2ProtectedResourceMetadata.Builder> customizer = null;

	private ResourceIdentifier resourceIdentifier = new ResourceIdentifier("/mcp");

	private boolean validateAudienceClaim = false;

	private NimbusJwtDecoder decoder = null;

	public McpServerOAuth2Configurer authorizationServer(String issuerUri) {
		this.issuerUri = issuerUri;
		return this;
	}

	public McpServerOAuth2Configurer scope(String scope) {
		this.scopes.add(scope);
		return this;
	}

	public McpServerOAuth2Configurer bearerMethod(String bearerMethod) {
		this.bearerMethod = bearerMethod;
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
		this.customizer = customizer;
		return this;
	}

	public McpServerOAuth2Configurer validateAudienceClaim(boolean validateAudienceClaim) {
		this.validateAudienceClaim = validateAudienceClaim;
		return this;
	}

	public McpServerOAuth2Configurer jwtDecoder(NimbusJwtDecoder decoder) {
		this.decoder = decoder;
		return this;
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		Assert.notNull(this.issuerUri, "authorizationServer cannot be null");
		Assert.notNull(this.resourceIdentifier, "resourceIdentifier cannot be null");

		var protectedResourceMetadataEndpointFilter = new OAuth2ProtectedResourceMetadataEndpointFilter(
				this.resourceIdentifier);
		protectedResourceMetadataEndpointFilter
			.setProtectedResourceMetadataCustomizer(getProtectedMetadataCustomizer());

		var entryPoint = new BearerResourceMetadataTokenAuthenticationEntryPoint(this.resourceIdentifier);
		var jwtDecoder = buildJwtDecoder();

		//@formatter:off
		http
				.oauth2ResourceServer(resourceServer -> {
					resourceServer.jwt(jwt -> jwt.decoder(jwtDecoder));
					resourceServer.authenticationEntryPoint(entryPoint);
				})
				.addFilterBefore(protectedResourceMetadataEndpointFilter, AbstractPreAuthenticatedProcessingFilter.class);
		//@formatter:on
	}

	private JwtDecoder buildJwtDecoder() {
		var decoder = this.decoder != null
			? this.decoder
			: NimbusJwtDecoder.withIssuerLocation(this.issuerUri).build();

		if (this.validateAudienceClaim) {
			OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators
				.createDefaultWithValidators(new JwtResourceValidator(this.resourceIdentifier));
			decoder.setJwtValidator(jwtValidator);
		}

		return decoder;
	}

	private Consumer<OAuth2ProtectedResourceMetadata.Builder> getProtectedMetadataCustomizer() {
		if (this.customizer != null) {
			return this.customizer;
		}
		return (protectedMetadata) -> protectedMetadata.authorizationServer(this.issuerUri)
			.resourceName(this.resourceName)
			.bearerMethod(this.bearerMethod);
	}

	public static McpServerOAuth2Configurer mcpServerOAuth2() {
		return new McpServerOAuth2Configurer();
	}

}
