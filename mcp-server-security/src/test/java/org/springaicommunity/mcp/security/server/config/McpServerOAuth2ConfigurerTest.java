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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.assertj.MockMvcTester;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer.mcpServerOAuth2;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
class McpServerOAuth2ConfigurerTest {

	private static final String ISSUER = "https://issuer.example.com";

	@Autowired
	WebApplicationContext wac;

	private MockMvcTester mvc;

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcTester.from(wac, builder -> builder.apply(springSecurity()).build());
	}

	@Test
	void metadataDefaults() {
		var resp = this.mvc.get().uri("/.well-known/oauth-protected-resource/defaults/mcp");
		assertThat(resp).hasStatus2xxSuccessful().bodyJson().isLenientlyEqualTo("""
				{
				  "authorization_servers": ["https://issuer.example.com"],
				  "resource_name": "Spring MCP Resource Server"
				}
				""");
	}

	@Test
	void metadataCustomizerKeepsDefaults() {
		var resp = this.mvc.get().uri("/.well-known/oauth-protected-resource/scopes/mcp");
		assertThat(resp).hasStatus2xxSuccessful().bodyJson().isLenientlyEqualTo("""
				{
				  "authorization_servers": ["https://issuer.example.com"],
				  "resource_name": "Spring MCP Resource Server",
				  "scopes_supported": ["mcp.read", "mcp.write"]
				}
				""");
	}

	@Test
	void metadataCustomizerKeepsCustomResourceName() {
		var resp = this.mvc.get().uri("/.well-known/oauth-protected-resource/resource-name/mcp");
		assertThat(resp).hasStatus2xxSuccessful().bodyJson().isLenientlyEqualTo("""
				{
				  "authorization_servers": ["https://issuer.example.com"],
				  "resource_name": "Custom Resource",
				  "scopes_supported": ["mcp.read"]
				}
				""");
	}

	@Test
	void metadataCustomizerOverridesDefaults() {
		var resp = this.mvc.get().uri("/.well-known/oauth-protected-resource/override/mcp");
		assertThat(resp).hasStatus2xxSuccessful().bodyJson().isLenientlyEqualTo("""
				{
				  "authorization_servers": ["https://issuer.example.com"],
				  "resource_name": "Overridden Resource"
				}
				""");
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebMvc
	@EnableWebSecurity
	static class TestConfig {

		@Bean
		SecurityFilterChain defaultsSecurityFilterChain(HttpSecurity http) {
			return http.securityMatcher("/defaults/**", "/.well-known/oauth-protected-resource/defaults/**")
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(mcpServerOAuth2(),
						oauth2 -> oauth2.authorizationServer(ISSUER)
							.resourcePath("/defaults/mcp")
							.jwtDecoder(mock(JwtDecoder.class)))
				.build();
		}

		@Bean
		SecurityFilterChain scopesSecurityFilterChain(HttpSecurity http) {
			return http.securityMatcher("/scopes/**", "/.well-known/oauth-protected-resource/scopes/**")
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(mcpServerOAuth2(), oauth2 -> oauth2.authorizationServer(ISSUER)
					.resourcePath("/scopes/mcp")
					.jwtDecoder(mock(JwtDecoder.class))
					.protectedResourceMetadataCustomizer(metadata -> metadata.scope("mcp.read").scope("mcp.write")))
				.build();
		}

		@Bean
		SecurityFilterChain resourceNameSecurityFilterChain(HttpSecurity http) {
			return http.securityMatcher("/resource-name/**", "/.well-known/oauth-protected-resource/resource-name/**")
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(mcpServerOAuth2(),
						oauth2 -> oauth2.authorizationServer(ISSUER)
							.resourcePath("/resource-name/mcp")
							.resourceName("Custom Resource")
							.jwtDecoder(mock(JwtDecoder.class))
							.protectedResourceMetadataCustomizer(metadata -> metadata.scope("mcp.read")))
				.build();
		}

		@Bean
		SecurityFilterChain overrideSecurityFilterChain(HttpSecurity http) {
			return http.securityMatcher("/override/**", "/.well-known/oauth-protected-resource/override/**")
				.authorizeHttpRequests(authz -> authz.anyRequest().authenticated())
				.with(mcpServerOAuth2(), oauth2 -> oauth2.authorizationServer(ISSUER)
					.resourcePath("/override/mcp")
					.jwtDecoder(mock(JwtDecoder.class))
					.protectedResourceMetadataCustomizer(metadata -> metadata.resourceName("Overridden Resource")))
				.build();
		}

	}

}
