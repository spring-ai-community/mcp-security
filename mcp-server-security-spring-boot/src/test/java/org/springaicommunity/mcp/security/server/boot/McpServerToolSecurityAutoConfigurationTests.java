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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpStatelessServerHandler;
import io.modelcontextprotocol.server.McpSyncListFilter;
import io.modelcontextprotocol.spec.McpSchema;
import io.modelcontextprotocol.spec.McpServerSession;
import io.modelcontextprotocol.spec.McpServerTransportProvider;
import io.modelcontextprotocol.spec.McpStatelessServerTransport;
import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.tool.MethodSecurityMcpToolFilter;
import reactor.core.publisher.Mono;

import org.springframework.ai.mcp.customizer.McpStatelessSyncServerCustomizer;
import org.springframework.ai.mcp.customizer.McpSyncServerCustomizer;
import org.springframework.ai.mcp.server.common.autoconfigure.annotations.McpServerAnnotationScannerAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link McpServerToolSecurityAutoConfiguration}.
 *
 * @author Yongtae Choi
 */
class McpServerToolSecurityAutoConfigurationTests {

	private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(McpServerAnnotationScannerAutoConfiguration.class,
				McpServerToolSecurityAutoConfiguration.class));

	@Test
	void registersToolFilter() {
		this.contextRunner.run((context) -> {
			assertThat(context).hasSingleBean(MethodSecurityMcpToolFilter.class);
			assertThat(context).hasSingleBean(McpStatelessSyncServerCustomizer.class);
		});
	}

	@Test
	void statelessCustomizerAddsToolFilterOnce() {
		this.contextRunner.run((context) -> {
			var customizer = context.getBean(McpStatelessSyncServerCustomizer.class);
			var builder = McpServer.sync(new StubStatelessTransport());

			customizer.customize(builder);
			customizer.customize(builder);

			assertThat(toolFilters(builder)).containsExactly(context.getBean(MethodSecurityMcpToolFilter.class));
		});
	}

	@Test
	void decoratesServerCustomizer() {
		this.contextRunner.withUserConfiguration(ServerCustomizerConfiguration.class).run((context) -> {
			var customizer = context.getBean(McpSyncServerCustomizer.class);
			var builder = McpServer.sync(new StubTransportProvider());

			customizer.customize(builder);
			customizer.customize(builder);

			assertThat(context.getBean(ServerCustomizerConfiguration.class).invocations).hasValue(2);
			assertThat(toolFilters(builder)).containsExactly(context.getBean(MethodSecurityMcpToolFilter.class));
		});
	}

	@Test
	void decoratedServerCustomizerKeepsItsInterfaces() {
		this.contextRunner.withUserConfiguration(OrderedServerCustomizerConfiguration.class).run((context) -> {
			var customizer = context.getBean(OrderedServerCustomizer.class);
			var builder = McpServer.sync(new StubTransportProvider());

			customizer.customize(builder);

			assertThat(customizer.getOrder()).isEqualTo(42);
			assertThat(toolFilters(builder)).containsExactly(context.getBean(MethodSecurityMcpToolFilter.class));
		});
	}

	@Test
	void backsOffWhenToolFilterIsDefined() {
		this.contextRunner.withUserConfiguration(CustomToolFilterConfiguration.class).run((context) -> {
			assertThat(context).hasSingleBean(MethodSecurityMcpToolFilter.class);
			assertThat(context).hasBean("customToolFilter");
		});
	}

	@Test
	void disabledByProperty() {
		this.contextRunner.withPropertyValues("spring.ai.mcp.server.security.tool-filter.enabled=false")
			.run((context) -> {
				assertThat(context).doesNotHaveBean(MethodSecurityMcpToolFilter.class);
				assertThat(context).doesNotHaveBean(McpStatelessSyncServerCustomizer.class);
			});
	}

	@Test
	void requiresAnnotationScanner() {
		new WebApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(McpServerToolSecurityAutoConfiguration.class))
			.run((context) -> assertThat(context).doesNotHaveBean(MethodSecurityMcpToolFilter.class));
	}

	@Test
	void requiresServletApplication() {
		new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(McpServerAnnotationScannerAutoConfiguration.class,
					McpServerToolSecurityAutoConfiguration.class))
			.run((context) -> assertThat(context).doesNotHaveBean(MethodSecurityMcpToolFilter.class));
	}

	private static List<McpSyncListFilter<McpSchema.Tool>> toolFilters(McpServer.SyncSpecification<?> builder) {
		List<McpSyncListFilter<McpSchema.Tool>> toolFilters = new ArrayList<>();
		builder.toolFilters(toolFilters::addAll);
		return toolFilters;
	}

	private static List<McpSyncListFilter<McpSchema.Tool>> toolFilters(McpServer.StatelessSyncSpecification builder) {
		List<McpSyncListFilter<McpSchema.Tool>> toolFilters = new ArrayList<>();
		builder.toolFilters(toolFilters::addAll);
		return toolFilters;
	}

	@Configuration(proxyBeanMethods = false)
	static class ServerCustomizerConfiguration {

		final AtomicInteger invocations = new AtomicInteger();

		@Bean
		McpSyncServerCustomizer serverCustomizer() {
			return (serverBuilder) -> this.invocations.incrementAndGet();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class OrderedServerCustomizerConfiguration {

		@Bean
		OrderedServerCustomizer serverCustomizer() {
			return new OrderedServerCustomizer();
		}

	}

	static class OrderedServerCustomizer implements McpSyncServerCustomizer, Ordered {

		@Override
		public void customize(McpServer.SyncSpecification<?> serverBuilder) {
		}

		@Override
		public int getOrder() {
			return 42;
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class CustomToolFilterConfiguration {

		@Bean
		MethodSecurityMcpToolFilter customToolFilter() {
			return new MethodSecurityMcpToolFilter((toolName) -> null);
		}

	}

	static class StubTransportProvider implements McpServerTransportProvider {

		@Override
		public void setSessionFactory(McpServerSession.Factory sessionFactory) {
		}

		@Override
		public Mono<Void> notifyClients(String method, Object params) {
			return Mono.empty();
		}

		@Override
		public Mono<Void> closeGracefully() {
			return Mono.empty();
		}

	}

	static class StubStatelessTransport implements McpStatelessServerTransport {

		@Override
		public void setMcpHandler(McpStatelessServerHandler mcpHandler) {
		}

		@Override
		public Mono<Void> closeGracefully() {
			return Mono.empty();
		}

	}

}
