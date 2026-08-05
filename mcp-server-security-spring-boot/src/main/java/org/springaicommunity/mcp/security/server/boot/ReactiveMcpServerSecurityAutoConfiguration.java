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

import org.springaicommunity.mcp.security.server.web.OriginValidationWebFilter;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.web.reactive.ReactiveOAuth2ResourceServerWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.WebFilter;

/**
 * {@link AutoConfiguration} for MCP server security in a reactive application.
 * <p>
 * Contributes a {@link Customizer}&lt;{@link ServerHttpSecurity}&gt; bean, which Spring
 * Security applies to every {@link ServerHttpSecurity} instance in the context. As a
 * result, the {@link OriginValidationWebFilter} is added to every
 * {@link SecurityWebFilterChain}, whether it is built by Spring Boot or by the
 * application itself.
 *
 * @author Daniel Garnier-Moiroux
 * @see McpServerSecurityProperties
 */
@AutoConfiguration(before = ReactiveOAuth2ResourceServerWebSecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({ EnableWebFluxSecurity.class, ServerHttpSecurity.class, WebFilter.class })
@EnableConfigurationProperties(McpServerSecurityProperties.class)
class ReactiveMcpServerSecurityAutoConfiguration {

	@Bean
	Customizer<ServerHttpSecurity> mcpServerOriginValidationCustomizer(McpServerSecurityProperties mcpProperties) {
		var originValidationFilter = new OriginValidationWebFilter(mcpProperties.getAllowedOrigins(),
				mcpProperties.getAllowedHosts());
		return (http) -> http.addFilterAfter(originValidationFilter, SecurityWebFiltersOrder.CORS);
	}

}
