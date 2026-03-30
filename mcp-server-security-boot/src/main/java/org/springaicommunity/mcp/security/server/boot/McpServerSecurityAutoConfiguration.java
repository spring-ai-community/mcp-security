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

package org.springaicommunity.mcp.security.server.boot;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.web.servlet.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import static org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer.mcpServerOAuth2;

/**
 * {@link AutoConfiguration} for MCP server security. Provides a default
 * {@link SecurityFilterChain} that secures all endpoints using the
 * {@code mcpServerOAuth2} configurer, reading the issuer URI from
 * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}.
 *
 * @author Daniel Garnier-Moiroux
 */
@AutoConfiguration(before = OAuth2ResourceServerAutoConfiguration.class)
@ConditionalOnDefaultWebSecurity
@EnableConfigurationProperties(OAuth2ResourceServerProperties.class)
@ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver", name = "jwt.issuer-uri",
		matchIfMissing = false)
public class McpServerSecurityAutoConfiguration {

	@Bean
	SecurityFilterChain mcpServerSecurityFilterChain(HttpSecurity http, OAuth2ResourceServerProperties properties) {
		var issuerUri = properties.getJwt().getIssuerUri();
		// Always true with @ConditonalOnProperty
		Assert.notNull(issuerUri, "spring.security.oauth2.resourceserver.jwt.issuer-uri must be set");
		return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
			.with(mcpServerOAuth2(), (mcpAuthorization) -> mcpAuthorization.authorizationServer(issuerUri))
			.build();
	}

}
