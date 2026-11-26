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

package org.springaicommunity.mcp.security.server.config;

import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class McpServerOAuth2ConfigurerTests {

	@Test
	void authorizationServerConfiguresSingleIssuer() {
		var configurer = new McpServerOAuth2Configurer().authorizationServer("https://issuer.example.com");

		assertThat(configurer.issuerUri).isEqualTo("https://issuer.example.com");
		assertThat(configurer.authorizationServers).containsExactly("https://issuer.example.com");
	}

	@Test
	void configuresMultipleAuthorizationServersAndAuthenticationManagerResolver() {
		AuthenticationManagerResolver<HttpServletRequest> resolver = mock();
		var configurer = new McpServerOAuth2Configurer()
			.authorizationServers(List.of("https://keycloak.example.com/realms/tenant-a",
					"https://keycloak.example.com/realms/tenant-b"))
			.authenticationManagerResolver(resolver);

		assertThat(configurer.authorizationServers).containsExactly("https://keycloak.example.com/realms/tenant-a",
				"https://keycloak.example.com/realms/tenant-b");
		assertThat(configurer.authenticationManagerResolver).isSameAs(resolver);
		assertThat(configurer.issuerUri).isNull();
	}

	@Test
	void configuresMultipleAuthorizationServersAndTenantAwareJwtDecoder() {
		var jwtDecoder = mock(JwtDecoder.class);
		var configurer = new McpServerOAuth2Configurer()
			.authorizationServers(List.of("https://keycloak.example.com/realms/tenant-a",
					"https://keycloak.example.com/realms/tenant-b"))
			.jwtDecoder(jwtDecoder);

		assertThat(configurer.authorizationServers).hasSize(2);
		assertThat(configurer.jwtDecoder).isSameAs(jwtDecoder);
		assertThat(configurer.issuerUri).isNull();
	}

}
