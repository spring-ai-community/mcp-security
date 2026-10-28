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

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;
import org.springaicommunity.mcp.security.server.tool.McpToolMethod;
import org.springaicommunity.mcp.security.server.tool.McpToolMethodResolver;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.annotation.common.McpPredicates;
import org.springframework.ai.mcp.annotation.spring.AnnotationProviderUtil;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Resolves tools declared with Spring AI's {@link McpTool} annotation, using the method
 * discovery and naming rules of Spring AI's synchronous tool providers: the tool name is
 * {@link McpTool#name()}, or the method name when it is blank, and methods with a
 * reactive return type are ignored. Tool names are expected to be unique: when several
 * methods declare the same name, the first one found is used.
 * <p>
 * The beans are read once, on first resolution, so that every annotated bean has been
 * initialized by the time the first {@code tools/list} request is served.
 *
 * @author Yongtae Choi
 */
public final class AnnotatedMcpToolMethodResolver implements McpToolMethodResolver {

	private static final Log logger = LogFactory.getLog(AnnotatedMcpToolMethodResolver.class);

	private final Supplier<? extends Collection<?>> beans;

	private volatile @Nullable Map<String, McpToolMethod> toolMethods;

	/**
	 * Create a resolver for the {@link McpTool} methods of the given beans.
	 * @param beans supplies the beans declaring {@link McpTool} methods, typically Spring
	 * AI's {@code ServerMcpAnnotatedBeans}
	 */
	public AnnotatedMcpToolMethodResolver(Supplier<? extends Collection<?>> beans) {
		Assert.notNull(beans, "beans cannot be null");
		this.beans = beans;
	}

	@Override
	public @Nullable McpToolMethod resolve(String toolName) {
		return getToolMethods().get(toolName);
	}

	private Map<String, McpToolMethod> getToolMethods() {
		var toolMethods = this.toolMethods;
		if (toolMethods == null) {
			synchronized (this) {
				toolMethods = this.toolMethods;
				if (toolMethods == null) {
					toolMethods = scan(this.beans.get());
					this.toolMethods = toolMethods;
				}
			}
		}
		return toolMethods;
	}

	private static Map<String, McpToolMethod> scan(Collection<?> beans) {
		Map<String, McpToolMethod> toolMethods = new HashMap<>();
		for (Object bean : beans) {
			for (Method method : AnnotationProviderUtil.beanMethods(bean)) {
				McpTool annotation = method.getAnnotation(McpTool.class);
				if (annotation == null || McpPredicates.isReactiveReturnType.test(method)) {
					continue;
				}
				String toolName = StringUtils.hasText(annotation.name()) ? annotation.name() : method.getName();
				McpToolMethod existing = toolMethods.putIfAbsent(toolName, new McpToolMethod(bean, method));
				if (existing != null) {
					logger.warn("Duplicate MCP tool name [%s] declared by [%s] and [%s], using the former"
						.formatted(toolName, existing.method(), method));
				}
			}
		}
		return Map.copyOf(toolMethods);
	}

}
