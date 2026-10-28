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
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springaicommunity.mcp.security.server.tool.McpToolMethod;
import reactor.core.publisher.Mono;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.aop.framework.ProxyFactory;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AnnotatedMcpToolMethodResolver}.
 *
 * @author Yongtae Choi
 */
class AnnotatedMcpToolMethodResolverTests {

	@Test
	void resolvesExplicitName() throws Exception {
		var tools = new Tools();
		var resolver = new AnnotatedMcpToolMethodResolver(() -> List.of(tools));

		assertThat(resolver.resolve("explicit-name"))
			.isEqualTo(new McpToolMethod(tools, Tools.class.getMethod("explicitName")));
	}

	@Test
	void defaultsToMethodName() throws Exception {
		var tools = new Tools();
		var resolver = new AnnotatedMcpToolMethodResolver(() -> List.of(tools));

		assertThat(resolver.resolve("defaultName"))
			.isEqualTo(new McpToolMethod(tools, Tools.class.getMethod("defaultName")));
	}

	@Test
	void ignoresUnknownToolsAndMethodsWithoutAnnotation() {
		var resolver = new AnnotatedMcpToolMethodResolver(() -> List.of(new Tools()));

		assertThat(resolver.resolve("notATool")).isNull();
		assertThat(resolver.resolve("unknown")).isNull();
	}

	@Test
	void ignoresReactiveToolsLikeSynchronousServers() throws Exception {
		var tools = new Tools();
		var resolver = new AnnotatedMcpToolMethodResolver(() -> List.of(tools));

		assertThat(resolver.resolve("reactive")).isNull();
		assertThat(resolver.resolve("overloaded"))
			.isEqualTo(new McpToolMethod(tools, Tools.class.getMethod("overloadedSync")));
	}

	@Test
	void resolvesProxyWithTargetMethod() throws Exception {
		var proxyFactory = new ProxyFactory(new Tools());
		proxyFactory.setProxyTargetClass(true);
		var proxy = proxyFactory.getProxy();
		var resolver = new AnnotatedMcpToolMethodResolver(() -> List.of(proxy));

		var toolMethod = resolver.resolve("explicit-name");

		assertThat(toolMethod).isNotNull();
		assertThat(toolMethod.bean()).isSameAs(proxy);
		assertThat(toolMethod.method()).isEqualTo(Tools.class.getMethod("explicitName"));
	}

	@Test
	void firstBeanWinsOnDuplicateName() throws Exception {
		var first = new Tools();
		var second = new Tools();
		var resolver = new AnnotatedMcpToolMethodResolver(() -> List.of(first, second));

		assertThat(resolver.resolve("explicit-name")).extracting(McpToolMethod::bean).isSameAs(first);
	}

	@Test
	void readsBeansOnceOnFirstResolution() {
		var reads = new AtomicInteger();
		var resolver = new AnnotatedMcpToolMethodResolver(() -> {
			reads.incrementAndGet();
			return List.of(new Tools());
		});

		assertThat(reads).hasValue(0);
		resolver.resolve("explicit-name");
		resolver.resolve("defaultName");
		assertThat(reads).hasValue(1);
	}

	static class Tools {

		@McpTool(name = "explicit-name", description = "explicit")
		public String explicitName() {
			return "explicit";
		}

		@McpTool(description = "default")
		public String defaultName() {
			return "default";
		}

		public String notATool() {
			return "not a tool";
		}

		@McpTool(name = "reactive", description = "reactive")
		public Mono<String> reactive() {
			return Mono.just("reactive");
		}

		@McpTool(name = "overloaded", description = "reactive")
		public Mono<String> overloadedAsync() {
			return Mono.just("async");
		}

		@McpTool(name = "overloaded", description = "sync")
		public String overloadedSync() {
			return "sync";
		}

	}

}
