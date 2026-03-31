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

import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import static org.assertj.core.api.Assertions.assertThat;

class McpServerSecurityAutoConfigurationTests {

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner().withConfiguration(
			AutoConfigurations.of(SecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class,
					OAuth2ResourceServerAutoConfiguration.class, McpServerSecurityAutoConfiguration.class));

	@Test
	void createFilterChain() {
		this.contextRunner
			.withPropertyValues("spring.security.oauth2.resourceserver.jwt.issuer-uri=https://example.com/issuer")
			.run((context) -> {
				// The context fails to start because it tries to resolve the JWT
				// decoder from the issuer URI, which is unreachable in tests. This
				// proves the auto-configuration was applied and tried to build the
				// SecurityFilterChain with the McpServerOAuth2Configurer.
				assertThat(context).hasFailed();
				assertThat(context.getStartupFailure()).hasMessageContaining("mcpServerSecurityFilterChain");
			});
	}

	@Test
	void userDefinedFilterChain() {
		this.contextRunner.withUserConfiguration(CustomSecurityConfiguration.class).run((context) -> {
			assertThat(context).hasSingleBean(SecurityFilterChain.class);
			assertThat(context).hasBean("customSecurityFilterChain");
			assertThat(context).doesNotHaveBean("mcpServerSecurityFilterChain");
		});
	}

	@Test
	void userDefinedFilterChainAndJwtUri() {
		this.contextRunner
			.withPropertyValues("spring.security.oauth2.resourceserver.jwt.issuer-uri=https://example.com/issuer")
			.withUserConfiguration(CustomSecurityConfiguration.class)
			.run((context) -> {
				assertThat(context).hasSingleBean(SecurityFilterChain.class);
				assertThat(context).hasBean("customSecurityFilterChain");
				assertThat(context).doesNotHaveBean("mcpServerSecurityFilterChain");
			});
	}

	@Test
	void issuerUriNotSet() {
		this.contextRunner.run((context) -> assertThat(context).getBeanNames(SecurityFilterChain.class)
			.containsExactly("defaultSecurityFilterChain"));
	}

	@Configuration(proxyBeanMethods = false)
	static class CustomSecurityConfiguration {

		@Bean
		SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
			return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).build();
		}

	}

}
