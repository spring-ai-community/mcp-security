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

package org.springaicommunity.mcp.security.authorizationserver.boot;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.security.oauth2.server.authorization.autoconfigure.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import org.springaicommunity.mcp.security.authorizationserver.config.McpAuthorizationServerConfigurer;

/**
 * @author Daniel Garnier-Moiroux
 */
class McpAuthorizationServerAutoConfigurationTests {

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class,
				ServletWebSecurityAutoConfiguration.class, OAuth2AuthorizationServerAutoConfiguration.class,
				OAuth2AuthorizationServerJwtAutoConfiguration.class, McpAuthorizationServerAutoConfiguration.class));

	@Test
	void createFilterChain() {
		this.contextRunner.run((context) -> {
			assertThat(context).getBeanNames(SecurityFilterChain.class)
				.hasSize(2)
				.containsExactly("authorizationServerSecurityFilterChain", "defaultSecurityFilterChain");
		});
	}

	@Test
	void userDefinedFilterChain() {
		this.contextRunner.withUserConfiguration(CustomSecurityConfiguration.class).run((context) -> {
			assertThat(context).hasSingleBean(SecurityFilterChain.class);
			assertThat(context).hasBean("customSecurityFilterChain");
			assertThat(context).doesNotHaveBean("authorizationServerSecurityFilterChain");
			assertThat(context).doesNotHaveBean("defaultSecurityFilterChain");
		});
	}

	@Test
	void noRegisteredClient() {
		this.contextRunner.run((context) -> {
			assertThat(context).hasSingleBean(RegisteredClientRepository.class);
			RegisteredClientRepository repository = context.getBean(RegisteredClientRepository.class);
			assertThat(repository).isInstanceOf(InMemoryRegisteredClientRepository.class);
			assertThat(repository.findByClientId("default")).isNotNull();
		});
	}

	@Test
	void registeredClientProperties() {
		this.contextRunner.withPropertyValues(
				"spring.security.oauth2.authorizationserver.client.test-client.registration.client-id=my-client",
				"spring.security.oauth2.authorizationserver.client.test-client.registration.client-secret={noop}secret",
				"spring.security.oauth2.authorizationserver.client.test-client.registration.client-authentication-methods=client_secret_basic",
				"spring.security.oauth2.authorizationserver.client.test-client.registration.authorization-grant-types=client_credentials")
			.run((context) -> {
				assertThat(context).hasSingleBean(RegisteredClientRepository.class);
				RegisteredClientRepository repository = context.getBean(RegisteredClientRepository.class);
				assertThat(repository.findByClientId("my-client")).isNotNull();
				assertThat(repository.findByClientId("default")).isNull();
			});
	}

	@Test
	void useDefaultDcrRegisteredClientRepository() {
		this.contextRunner.withUserConfiguration(CustomRegisteredClientRepositoryConfiguration.class).run((context) -> {
			assertThat(context).hasSingleBean(RegisteredClientRepository.class);
			RegisteredClientRepository repository = context.getBean(RegisteredClientRepository.class);
			assertThat(repository.findByClientId("custom-client")).isNotNull();
			assertThat(repository.findByClientId("default")).isNull();
		});
	}

	@Test
	void dynamicClientRegistrationDisabled() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.authorizationserver.dynamic-client-registration.enabled=false")
			.run((context) -> {
				assertThat(context).hasFailed()
					.getFailure()
					.hasMessageContaining(
							"No qualifying bean of type 'org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository'");
			});
	}

	@Test
	void dynamicClientRegistrationDisabledWithRegistrations() {
		this.contextRunner.withPropertyValues(
				"spring.ai.mcp.authorizationserver.dynamic-client-registration.enabled=false",
				"spring.security.oauth2.authorizationserver.client.test-client.registration.client-id=my-client",
				"spring.security.oauth2.authorizationserver.client.test-client.registration.client-secret={noop}secret",
				"spring.security.oauth2.authorizationserver.client.test-client.registration.client-authentication-methods=client_secret_basic",
				"spring.security.oauth2.authorizationserver.client.test-client.registration.authorization-grant-types=client_credentials")
			.run((context) -> {
				RegisteredClientRepository repository = context.getBean(RegisteredClientRepository.class);
				assertThat(repository.findByClientId("my-client")).isNotNull();
				assertThat(repository.findByClientId("default")).isNull();
			});
	}

	@Test
	void dynamicClientRegistrationDisabledWithCustomRepository() {
		this.contextRunner.withUserConfiguration(CustomRegisteredClientRepositoryConfiguration.class)
			.withPropertyValues("spring.ai.mcp.authorizationserver.dynamic-client-registration.enabled=false")
			.run((context) -> {
				assertThat(context).hasNotFailed();
			});
	}

	@Test
	void customizerIsApplied() {
		this.contextRunner.withUserConfiguration(CustomizerConfiguration.class).run((context) -> {
			Customizer<?> customizer = context.getBean(Customizer.class);
			verify(customizer).customize(any());
		});
	}

	@Test
	void dynamicClientRegistrationTokenSettingsProperties() {
		this.contextRunner
			.withPropertyValues("spring.ai.mcp.authorizationserver.token.access-token-time-to-live=15m",
					"spring.ai.mcp.authorizationserver.token.refresh-token-time-to-live=7d",
					"spring.ai.mcp.authorizationserver.token.reuse-refresh-tokens=false")
			.run((context) -> {
				Filter springSecurityFilterChain = context.getBean("springSecurityFilterChain", Filter.class);
				MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/register");
				request.setContentType(MediaType.APPLICATION_JSON_VALUE);
				request.setContent("""
						{
							"redirect_uris": ["https://example.com/callback"]
						}
						""".getBytes(StandardCharsets.UTF_8));
				MockHttpServletResponse response = new MockHttpServletResponse();

				springSecurityFilterChain.doFilter(request, response, new MockFilterChain());

				assertThat(response.getStatus()).isEqualTo(HttpStatus.CREATED.value());

				var mapper = JsonMapper.builder().build();
				var body = mapper.readValue(response.getContentAsByteArray(), Map.class);
				var clientId = body.get("client_id");
				assertThat(clientId).isNotNull();

				RegisteredClient client = context.getBean(RegisteredClientRepository.class)
					.findByClientId(clientId.toString());
				assertThat(client).isNotNull();
				assertThat(client.getTokenSettings().getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(15));
				assertThat(client.getTokenSettings().getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(7));
				assertThat(client.getTokenSettings().isReuseRefreshTokens()).isFalse();
			});
	}

	@Configuration(proxyBeanMethods = false)
	static class CustomizerConfiguration {

		@Bean
		@SuppressWarnings("unchecked")
		Customizer<McpAuthorizationServerConfigurer> mcpCustomizer() {
			return mock(Customizer.class);
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class CustomSecurityConfiguration {

		@Bean
		SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
			return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class CustomRegisteredClientRepositoryConfiguration {

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			RegisteredClient client = RegisteredClient.withId("custom")
				.clientId("custom-client")
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.build();
			return new InMemoryRegisteredClientRepository(client);
		}

	}

}
