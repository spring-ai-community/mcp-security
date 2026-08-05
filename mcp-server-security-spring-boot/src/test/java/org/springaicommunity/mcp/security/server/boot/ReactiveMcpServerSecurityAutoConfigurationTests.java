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

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.web.OriginValidationWebFilter;
import reactor.core.publisher.Mono;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.web.reactive.ReactiveWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.assertj.AssertableReactiveWebApplicationContext;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;
import static org.assertj.core.api.Assertions.assertThat;

class ReactiveMcpServerSecurityAutoConfigurationTests {

	private final ReactiveWebApplicationContextRunner contextRunner = new ReactiveWebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(ReactiveWebSecurityAutoConfiguration.class,
				ReactiveMcpServerSecurityAutoConfiguration.class));

	@Test
	void addsOriginValidationWebFilterToFilterChain() {
		this.contextRunner.withUserConfiguration(CustomSecurityConfiguration.class).run((context) -> {
			assertThat(context).hasBean("mcpServerOriginValidationCustomizer");
			assertThat(originValidationFilter(context)).isNotNull();
		});
	}

	@Test
	void defaultsToLocalOrigins() {
		this.contextRunner.withUserConfiguration(CustomSecurityConfiguration.class).run((context) -> {
			assertThat(statusFor(originValidationFilter(context), "http://localhost:8080")).isNull();
			assertThat(statusFor(originValidationFilter(context), "https://evil.example.com"))
				.isEqualTo(HttpStatus.FORBIDDEN);
		});
	}

	@Test
	void allowedOriginsAreConfigurable() {
		this.contextRunner.withUserConfiguration(CustomSecurityConfiguration.class)
			.withPropertyValues("spring.ai.mcp.server.security.allowed-origins=https://allowed.example.com")
			.run((context) -> {
				assertThat(statusFor(originValidationFilter(context), "https://allowed.example.com")).isNull();
				assertThat(statusFor(originValidationFilter(context), "http://localhost:8080"))
					.isEqualTo(HttpStatus.FORBIDDEN);
			});
	}

	@Test
	void notAppliedToServletApplications() {
		new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(ReactiveMcpServerSecurityAutoConfiguration.class))
			.run((context) -> assertThat(context).doesNotHaveBean("mcpServerOriginValidationCustomizer"));
	}

	private static OriginValidationWebFilter originValidationFilter(AssertableReactiveWebApplicationContext context) {
		List<WebFilter> filters = Objects
			.requireNonNull(context.getBean(SecurityWebFilterChain.class).getWebFilters().collectList().block());
		return filters.stream()
			.filter(OriginValidationWebFilter.class::isInstance)
			.map(OriginValidationWebFilter.class::cast)
			.findFirst()
			.orElseThrow(() -> new AssertionError("No OriginValidationWebFilter in " + filters));
	}

	/**
	 * Runs the filter against a request with the given {@code Origin} header, and returns
	 * the rejection status, or {@code null} when the request was allowed through.
	 */
	private static @Nullable HttpStatus statusFor(OriginValidationWebFilter filter, String origin) {
		var exchange = MockServerWebExchange
			.from(MockServerHttpRequest.get("/mcp").header(HttpHeaders.ORIGIN, origin).build());
		filter.filter(exchange, (unused) -> Mono.empty()).block();
		var status = exchange.getResponse().getStatusCode();
		return (status != null) ? HttpStatus.valueOf(status.value()) : null;
	}

	@Configuration(proxyBeanMethods = false)
	static class CustomSecurityConfiguration {

		@Bean
		SecurityWebFilterChain customSecurityWebFilterChain(ServerHttpSecurity http) {
			return http.authorizeExchange((exchanges) -> exchanges.anyExchange().permitAll()).build();
		}

	}

}
