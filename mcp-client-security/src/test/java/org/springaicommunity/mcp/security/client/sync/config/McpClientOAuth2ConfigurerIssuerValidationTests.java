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

package org.springaicommunity.mcp.security.client.sync.config;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.Filter;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.client.sync.oauth2.registration.InMemoryMcpClientRegistrationRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.NestedTestConfiguration;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Checks that {@link McpClientOAuth2Configurer} validates the RFC 9207 {@code iss}
 * parameter of authorization responses, through the whole Spring Security authorization
 * code flow.
 *
 * @author Daniel Garnier-Moiroux
 */
@SpringJUnitWebConfig(McpClientOAuth2ConfigurerIssuerValidationTests.SecurityConfiguration.class)
class McpClientOAuth2ConfigurerIssuerValidationTests {

	private static final String ISSUER = "http://localhost:1";

	@Autowired
	private WebApplicationContext context;

	private MockMvc mvc;

	private final MockHttpSession session = new MockHttpSession();

	@BeforeEach
	void setUp() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context)
			.addFilters(this.context.getBean("springSecurityFilterChain", Filter.class))
			.build();
	}

	@Test
	void wrongIssIsRejected() throws Exception {
		var state = authorize("advertised");

		var error = callback("advertised", state, "https://evil.example.com");

		assertThat(error).isEqualTo("invalid_iss_parameter");
	}

	@Test
	void missingIssIsRejectedWhenAdvertised() throws Exception {
		var state = authorize("advertised");

		var error = callback("advertised", state, null);

		assertThat(error).isEqualTo("invalid_iss_parameter");
	}

	@Test
	void missingIssIsAcceptedWhenNotAdvertised() throws Exception {
		var state = authorize("not-advertised");

		var error = callback("not-advertised", state, null);

		// The token endpoint does not exist: the client tried to redeem the code
		assertThat(error).isEqualTo("invalid_token_response");
	}

	@Test
	void matchingIssIsAccepted() throws Exception {
		var state = authorize("advertised");

		var error = callback("advertised", state, ISSUER);

		// The token endpoint does not exist: the client tried to redeem the code
		assertThat(error).isEqualTo("invalid_token_response");
	}

	@Test
	void issIsRejectedWithoutIssuer() throws Exception {
		var state = authorize("no-issuer");

		var error = callback("no-issuer", state, ISSUER);

		assertThat(error).isEqualTo("invalid_iss_parameter");
	}

	@Test
	void missingIssIsAcceptedWithoutIssuer() throws Exception {
		var state = authorize("no-issuer");

		var error = callback("no-issuer", state, null);

		// The token endpoint does not exist: the client tried to redeem the code
		assertThat(error).isEqualTo("invalid_token_response");
	}

	/**
	 * Starts the authorization code flow, and returns the {@code state} of the
	 * authorization request.
	 */
	private String authorize(String registrationId) throws Exception {
		return authorize(this.mvc, this.session, registrationId);
	}

	private static String authorize(MockMvc mvc, MockHttpSession session, String registrationId) throws Exception {
		var location = mvc.perform(get("/oauth2/authorization/{id}", registrationId).session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn()
			.getResponse()
			.getRedirectedUrl();
		Objects.requireNonNull(location);
		assertThat(location).startsWith(ISSUER + "/authorize");
		var state = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("state");
		assertThat(state).isNotNull();
		return URLDecoder.decode(state, StandardCharsets.UTF_8);
	}

	/**
	 * Sends the authorization response to the client, and returns the error code the
	 * client redirects to.
	 */
	private @Nullable String callback(String registrationId, String state, @Nullable String iss) throws Exception {
		return callback(this.mvc, this.session, registrationId, state, iss);
	}

	private static @Nullable String callback(MockMvc mvc, MockHttpSession session, String registrationId, String state,
			@Nullable String iss) throws Exception {
		var uri = UriComponentsBuilder.fromPath("/authorize/oauth2/code/{id}")
			.queryParam("code", "the-code")
			.queryParam("state", state);
		if (iss != null) {
			uri.queryParam("iss", iss);
		}
		var location = mvc.perform(get(uri.buildAndExpand(registrationId).encode().toUri()).session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn()
			.getResponse()
			.getRedirectedUrl();
		Objects.requireNonNull(location);
		assertThat(location).startsWith("http://localhost/authorize/oauth2/code/" + registrationId);
		return UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("error");
	}

	@Nested
	@NestedTestConfiguration(NestedTestConfiguration.EnclosingConfiguration.OVERRIDE)
	@SpringJUnitWebConfig(IssParameterValidationDisabledConfiguration.class)
	class IssParameterValidationDisabled {

		@Autowired
		private WebApplicationContext context;

		private MockMvc mvc;

		private final MockHttpSession session = new MockHttpSession();

		@BeforeEach
		void setUp() {
			this.mvc = MockMvcBuilders.webAppContextSetup(this.context)
				.addFilters(this.context.getBean("springSecurityFilterChain", Filter.class))
				.build();
		}

		@Test
		void wrongIssIsAccepted() throws Exception {
			var state = authorize(this.mvc, this.session, "advertised");

			var error = callback(this.mvc, this.session, "advertised", state, "https://evil.example.com");

			// The token endpoint does not exist: the client tried to redeem the code
			assertThat(error).isEqualTo("invalid_token_response");
		}

		@Test
		void issIsAcceptedWithoutIssuer() throws Exception {
			var state = authorize(this.mvc, this.session, "no-issuer");

			var error = callback(this.mvc, this.session, "no-issuer", state, ISSUER);

			// The token endpoint does not exist: the client tried to redeem the code
			assertThat(error).isEqualTo("invalid_token_response");
		}

	}

	@Configuration
	@EnableWebSecurity
	static class IssParameterValidationDisabledConfiguration {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.with(new McpClientOAuth2Configurer(), mcp -> mcp.issParameterValidation(false))
				.build();
		}

		@Bean
		InMemoryMcpClientRegistrationRepository clientRegistrationRepository() {
			return SecurityConfiguration.clientRegistrationRepositoryWithRegistrations();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityConfiguration {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			return http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
				.with(new McpClientOAuth2Configurer(), mcp -> {
				})
				.build();
		}

		@Bean
		InMemoryMcpClientRegistrationRepository clientRegistrationRepository() {
			return clientRegistrationRepositoryWithRegistrations();
		}

		static InMemoryMcpClientRegistrationRepository clientRegistrationRepositoryWithRegistrations() {
			var repository = new InMemoryMcpClientRegistrationRepository();
			repository.addClientRegistration(registration("advertised", true), "http://localhost:2/mcp");
			repository.addClientRegistration(registration("not-advertised", false), "http://localhost:2/mcp");
			// Like a Spring Boot registration that configures the endpoints by hand
			repository.addClientRegistration(registrationWithoutIssuer("no-issuer"), "http://localhost:2/mcp");
			return repository;
		}

		private static ClientRegistration registration(String registrationId, boolean issParameterSupported) {
			return ClientRegistration.withRegistrationId(registrationId)
				.clientId("client-id")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("http://localhost/authorize/oauth2/code/" + registrationId)
				.authorizationUri(ISSUER + "/authorize")
				.tokenUri(ISSUER + "/token")
				.issuerUri(ISSUER)
				.providerConfigurationMetadata(Map.of("issuer", ISSUER,
						"authorization_response_iss_parameter_supported", issParameterSupported))
				.build();
		}

		private static ClientRegistration registrationWithoutIssuer(String registrationId) {
			return ClientRegistration.withRegistrationId(registrationId)
				.clientId("client-id")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUri("http://localhost/authorize/oauth2/code/" + registrationId)
				.authorizationUri(ISSUER + "/authorize")
				.tokenUri(ISSUER + "/token")
				.build();
		}

	}

}
