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

import java.lang.reflect.Modifier;
import java.util.List;
import java.util.function.Consumer;

import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpSyncListFilter;
import io.modelcontextprotocol.spec.McpSchema;
import org.aopalliance.intercept.MethodInterceptor;
import org.springaicommunity.mcp.security.server.tool.MethodSecurityMcpToolFilter;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.ai.mcp.customizer.McpStatelessSyncServerCustomizer;
import org.springframework.ai.mcp.customizer.McpSyncServerCustomizer;
import org.springframework.ai.mcp.server.common.autoconfigure.annotations.McpServerAnnotationScannerAutoConfiguration;
import org.springframework.ai.mcp.server.common.autoconfigure.annotations.McpServerAnnotationScannerAutoConfiguration.ServerMcpAnnotatedBeans;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.util.ClassUtils;

/**
 * {@link AutoConfiguration} that hides {@link McpTool @McpTool} tools from
 * {@code tools/list} when the caller is not authorized to call them through Spring
 * Security's method security. See {@link MethodSecurityMcpToolFilter}.
 * <p>
 * Applies to synchronous, servlet-based MCP servers, both stateful and stateless. It can
 * be disabled with {@code spring.ai.mcp.server.security.tool-filter.enabled=false}.
 *
 * @author Yongtae Choi
 */
@AutoConfiguration(after = McpServerAnnotationScannerAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ McpTool.class, ServerMcpAnnotatedBeans.class, McpSyncServerCustomizer.class,
		McpSyncListFilter.class, AuthorizationAdvisor.class })
@ConditionalOnBean(ServerMcpAnnotatedBeans.class)
@ConditionalOnProperty(prefix = McpServerToolFilterProperties.CONFIG_PREFIX, name = "enabled", havingValue = "true",
		matchIfMissing = true)
@EnableConfigurationProperties(McpServerToolFilterProperties.class)
class McpServerToolSecurityAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	MethodSecurityMcpToolFilter methodSecurityMcpToolFilter(ServerMcpAnnotatedBeans annotatedBeans) {
		return new MethodSecurityMcpToolFilter(
				new AnnotatedMcpToolMethodResolver(() -> annotatedBeans.getBeansByAnnotation(McpTool.class)));
	}

	@Bean
	McpStatelessSyncServerCustomizer methodSecurityMcpToolFilterStatelessServerCustomizer(
			MethodSecurityMcpToolFilter toolFilter) {
		return (serverBuilder) -> serverBuilder.toolFilters(addIfAbsent(toolFilter));
	}

	/**
	 * The stateful server accepts a single {@link McpSyncServerCustomizer}, and Spring AI
	 * already registers one for servlet applications. Decorate it rather than adding
	 * another one: the decorator is a proxy implementing the same interfaces.
	 */
	@Bean
	static BeanPostProcessor methodSecurityMcpToolFilterServerCustomizerPostProcessor(
			ObjectProvider<MethodSecurityMcpToolFilter> toolFilter) {
		return new BeanPostProcessor() {

			@Override
			public Object postProcessAfterInitialization(Object bean, String beanName) {
				if (!(bean instanceof McpSyncServerCustomizer)) {
					return bean;
				}
				ProxyFactory proxyFactory = new ProxyFactory(bean);
				Class<?> beanClass = bean.getClass();
				// keep the bean's type when it can be subclassed, lambdas only keep their
				// interfaces
				proxyFactory.setProxyTargetClass(
						!ClassUtils.isLambdaClass(beanClass) && !Modifier.isFinal(beanClass.getModifiers()));
				proxyFactory.addAdvice((MethodInterceptor) (invocation) -> {
					Object result = invocation.proceed();
					Object[] arguments = invocation.getArguments();
					if (invocation.getMethod().getName().equals("customize") && arguments != null
							&& arguments.length == 1
							&& arguments[0] instanceof McpServer.SyncSpecification<?> serverBuilder) {
						serverBuilder.toolFilters(addIfAbsent(toolFilter.getObject()));
					}
					return result;
				});
				return proxyFactory.getProxy(beanClass.getClassLoader());
			}

		};
	}

	private static Consumer<List<McpSyncListFilter<McpSchema.Tool>>> addIfAbsent(
			McpSyncListFilter<McpSchema.Tool> toolFilter) {
		return (toolFilters) -> {
			if (!toolFilters.contains(toolFilter)) {
				toolFilters.add(toolFilter);
			}
		};
	}

}
