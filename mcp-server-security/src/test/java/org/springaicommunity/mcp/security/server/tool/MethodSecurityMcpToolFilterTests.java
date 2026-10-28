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

package org.springaicommunity.mcp.security.server.tool;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.spec.McpSchema;
import jakarta.annotation.security.RolesAllowed;
import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.HandleAuthorizationDenied;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link MethodSecurityMcpToolFilter}.
 *
 * @author Yongtae Choi
 */
class MethodSecurityMcpToolFilterTests {

	private static final List<String> ALL_TOOLS = List.of("public", "authenticated", "user", "admin", "secured",
			"roles-allowed", "handled-denied", "by-owner", "by-owner-and-admin", "by-templated-owner",
			"by-owner-handled", "by-owner-bean", "pre-filtered", "post-authorized", "class-level", "interface-based",
			"unproxied", "unknown");

	private AnnotationConfigApplicationContext context;

	private MethodSecurityMcpToolFilter filter;

	@BeforeEach
	void setUp() {
		SecurityContextHolder.clearContext();
		this.context = new AnnotationConfigApplicationContext(MethodSecurityConfiguration.class);
		var beans = List.<Object>of(this.context.getBean(SecuredTools.class), this.context.getBean(AdminTools.class),
				this.context.getBean("interfaceTools"), new UnproxiedTools());
		this.filter = new MethodSecurityMcpToolFilter(toolMethods(beans));
	}

	@AfterEach
	void tearDown() {
		SecurityContextHolder.clearContext();
		this.context.close();
	}

	@Test
	void anonymousSeesUnsecuredTools() {
		authenticateAnonymously();

		assertThat(visibleTools()).containsExactlyInAnyOrder("public", "by-owner", "by-templated-owner",
				"by-owner-handled", "by-owner-bean", "post-authorized", "unproxied", "unknown");
	}

	@Test
	void userSeesToolsGrantedToUsers() {
		authenticate("alice", "ROLE_USER");

		assertThat(visibleTools()).containsExactlyInAnyOrder("public", "authenticated", "user", "by-owner",
				"by-templated-owner", "by-owner-handled", "by-owner-bean", "post-authorized", "unproxied", "unknown");
	}

	@Test
	void adminSeesEverythingThroughRoleHierarchy() {
		authenticate("bob", "ROLE_ADMIN");

		assertThat(visibleTools()).containsExactlyElementsOf(ALL_TOOLS);
	}

	@Test
	void classLevelAnnotationApplies() {
		authenticate("alice", "ROLE_USER");

		assertThat(isVisible("class-level")).isFalse();
	}

	@Test
	void interfaceBasedProxyIsHonored() {
		assertThat(Proxy.isProxyClass(this.context.getBean("interfaceTools").getClass())).isTrue();

		authenticate("alice", "ROLE_USER");
		assertThat(isVisible("interface-based")).isFalse();

		authenticate("bob", "ROLE_ADMIN");
		assertThat(isVisible("interface-based")).isTrue();
	}

	@Test
	void securedAndRolesAllowedAreHonored() {
		authenticate("alice", "ROLE_USER");

		assertThat(isVisible("secured")).isFalse();
		assertThat(isVisible("roles-allowed")).isFalse();
	}

	@Test
	void argumentDependentExpressionDoesNotHideTool() {
		authenticate("alice", "ROLE_USER");

		assertThat(isVisible("by-owner")).isTrue();
		assertThat(isVisible("by-templated-owner")).isTrue();
		assertThat(isVisible("by-owner-handled")).isTrue();
		assertThat(isVisible("by-owner-bean")).isTrue();
	}

	@Test
	void argumentDependentExpressionDoesNotBypassOtherAnnotations() {
		authenticate("alice", "ROLE_USER");
		assertThat(isVisible("by-owner-and-admin")).isFalse();

		authenticate("bob", "ROLE_ADMIN");
		assertThat(isVisible("by-owner-and-admin")).isTrue();
	}

	@Test
	void advisorThatCannotDecideDoesNotBypassOtherAdvisors() {
		authenticate("alice", "ROLE_USER");
		assertThat(isVisible("pre-filtered")).isFalse();

		authenticate("bob", "ROLE_ADMIN");
		assertThat(isVisible("pre-filtered")).isTrue();
	}

	@Test
	void deniedInvocationHandledByHandlerIsHidden() {
		authenticate("alice", "ROLE_USER");

		assertThat(isVisible("handled-denied")).isFalse();
	}

	@Test
	void missingAuthenticationHidesSecuredTools() {
		assertThat(isVisible("authenticated")).isFalse();
		assertThat(isVisible("public")).isTrue();
	}

	@Test
	void toolMethodsAreNeverInvoked() {
		var tools = this.context.getBean(SecuredTools.class);

		authenticate("alice", "ROLE_USER");
		visibleTools();
		authenticate("bob", "ROLE_ADMIN");
		visibleTools();

		assertThat(tools.invocationCount()).isZero();
	}

	@Test
	void decisionFollowsTheCurrentCaller() {
		authenticate("alice", "ROLE_USER");
		assertThat(isVisible("admin")).isFalse();

		authenticate("bob", "ROLE_ADMIN");
		assertThat(isVisible("admin")).isTrue();
	}

	private List<String> visibleTools() {
		return ALL_TOOLS.stream().filter(this::isVisible).toList();
	}

	private boolean isVisible(String toolName) {
		var tool = McpSchema.Tool.builder()
			.name(toolName)
			.inputSchema(new McpSchema.JsonSchema("object", null, null, null, null, null))
			.build();
		return this.filter.isVisible(McpTransportContext.EMPTY, tool);
	}

	private static void authenticate(String name, String... authorities) {
		SecurityContextHolder.getContext()
			.setAuthentication(new TestingAuthenticationToken(name, "password", authorities));
	}

	private static void authenticateAnonymously() {
		SecurityContextHolder.getContext()
			.setAuthentication(new AnonymousAuthenticationToken("key", "anonymous",
					AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
	}

	@Configuration(proxyBeanMethods = false)
	@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
	static class MethodSecurityConfiguration {

		@Bean
		static RoleHierarchy roleHierarchy() {
			return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
		}

		@Bean
		static AnnotationTemplateExpressionDefaults templateExpressionDefaults() {
			return new AnnotationTemplateExpressionDefaults();
		}

		@Bean
		SecuredTools securedTools() {
			return new SecuredTools();
		}

		@Bean
		AdminTools adminTools() {
			return new AdminTools();
		}

		@Bean
		ToolsApi interfaceTools() {
			return new InterfaceTools();
		}

		@Bean
		Ownership ownership() {
			return new Ownership();
		}

		@Bean
		FallbackDeniedHandler fallbackDeniedHandler() {
			return new FallbackDeniedHandler();
		}

	}

	/**
	 * Resolves the tools declared with {@link Tool} on the given beans.
	 */
	private static McpToolMethodResolver toolMethods(List<Object> beans) {
		Map<String, McpToolMethod> toolMethods = new HashMap<>();
		for (Object bean : beans) {
			for (Method method : AopProxyUtils.ultimateTargetClass(bean).getDeclaredMethods()) {
				Tool tool = method.getAnnotation(Tool.class);
				if (tool != null) {
					toolMethods.put(tool.value(), new McpToolMethod(bean, method));
				}
			}
		}
		return toolMethods::get;
	}

	/**
	 * Declares a tool, like Spring AI's {@code @McpTool}.
	 */
	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	@interface Tool {

		String value();

	}

	@Target(ElementType.METHOD)
	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("{value} == authentication.name")
	@interface IsOwner {

		String value();

	}

	static class SecuredTools {

		final AtomicInteger invocations = new AtomicInteger();

		@Tool("public")
		public String publicTool() {
			return invoked();
		}

		@PreAuthorize("isAuthenticated() and !isAnonymous()")
		@Tool("authenticated")
		public String authenticated() {
			return invoked();
		}

		@PreAuthorize("hasRole('USER')")
		@Tool("user")
		public String user() {
			return invoked();
		}

		@PreAuthorize("hasRole('ADMIN')")
		@Tool("admin")
		public String admin(String argument) {
			return invoked();
		}

		@Secured("ROLE_ADMIN")
		@Tool("secured")
		public String secured() {
			return invoked();
		}

		@RolesAllowed("ADMIN")
		@Tool("roles-allowed")
		public String rolesAllowed() {
			return invoked();
		}

		@PreAuthorize("hasRole('ADMIN')")
		@HandleAuthorizationDenied(handlerClass = FallbackDeniedHandler.class)
		@Tool("handled-denied")
		public String handledDenied() {
			return invoked();
		}

		@PreAuthorize("#owner == authentication.name")
		@Tool("by-owner")
		public String byOwner(String owner) {
			return invoked();
		}

		@Secured("ROLE_ADMIN")
		@PreAuthorize("#owner == authentication.name")
		@Tool("by-owner-and-admin")
		public String byOwnerAndAdmin(String owner) {
			return invoked();
		}

		@PreAuthorize("#owner == authentication.name")
		@HandleAuthorizationDenied(handlerClass = FallbackDeniedHandler.class)
		@Tool("by-owner-handled")
		public String byOwnerHandled(String owner) {
			return invoked();
		}

		@PreAuthorize("@ownership.check(#owner)")
		@Tool("by-owner-bean")
		public String byOwnerBean(String owner) {
			return invoked();
		}

		@IsOwner("#owner")
		@Tool("by-templated-owner")
		public String byTemplatedOwner(String owner) {
			return invoked();
		}

		@PreFilter("filterObject != 'forbidden'")
		@PreAuthorize("hasRole('ADMIN')")
		@Tool("pre-filtered")
		public String preFiltered(List<String> items) {
			return invoked();
		}

		@PostAuthorize("returnObject == 'nope'")
		@Tool("post-authorized")
		public String postAuthorized() {
			return invoked();
		}

		public int invocationCount() {
			return this.invocations.get();
		}

		private String invoked() {
			this.invocations.incrementAndGet();
			return "invoked";
		}

	}

	@PreAuthorize("hasRole('ADMIN')")
	static class AdminTools {

		@Tool("class-level")
		public String classLevel() {
			return "invoked";
		}

	}

	interface ToolsApi {

		String interfaceBased();

	}

	@PreAuthorize("hasRole('ADMIN')")
	static class InterfaceTools implements ToolsApi {

		@Override
		@Tool("interface-based")
		public String interfaceBased() {
			return "invoked";
		}

	}

	static class UnproxiedTools {

		@PreAuthorize("hasRole('ADMIN')")
		@Tool("unproxied")
		public String unproxied() {
			return "invoked";
		}

	}

	static class Ownership {

		public AuthorizationResult check(@Nullable String owner) {
			return new AuthorizationDecision(owner != null);
		}

	}

	static class FallbackDeniedHandler implements MethodAuthorizationDeniedHandler {

		@Override
		public @Nullable Object handleDeniedInvocation(MethodInvocation methodInvocation,
				AuthorizationResult authorizationResult) {
			return "denied";
		}

	}

}
