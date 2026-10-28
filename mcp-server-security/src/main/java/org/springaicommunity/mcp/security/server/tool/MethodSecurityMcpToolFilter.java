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

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import io.modelcontextprotocol.common.McpTransportContext;
import io.modelcontextprotocol.server.McpSyncListFilter;
import io.modelcontextprotocol.spec.McpSchema;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.aop.Advisor;
import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.ExpressionAuthorizationDecision;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

/**
 * An MCP tool list filter that hides a tool from {@code tools/list} when the current
 * caller would be denied calling it by Spring Security's method security, for example
 * with {@link PreAuthorize @PreAuthorize}, {@code @Secured} or {@code @RolesAllowed}.
 * <p>
 * The decision is made by the {@link AuthorizationAdvisor}s of the method-security proxy
 * that the tool is called through, so listing and calling a tool agree: the expression
 * handler, role hierarchy, annotation templates and authorization managers configured for
 * method security apply to both. Each advisor is run against a stand-in invocation that
 * never reaches the tool method, and whose arguments are all {@code null}: the tool is
 * visible when every advisor would let the call proceed.
 * <p>
 * A tool stays visible, and is only authorized when it is called, when:
 * <ul>
 * <li>it is not backed by a method known to the {@link McpToolMethodResolver};</li>
 * <li>its bean is not a Spring AOP proxy carrying method-security advisors, for example
 * with AspectJ-mode method security or with scoped proxies;</li>
 * <li>it is denied by an expression that references method arguments, such as
 * {@code #id == authentication.name}, since the arguments are only known when the tool is
 * called;</li>
 * <li>it is only secured by advisors that act after the method returns, such as
 * {@code @PostAuthorize};</li>
 * <li>an advisor fails with an exception other than an {@link AccessDeniedException} or
 * {@link AuthenticationException}.</li>
 * </ul>
 * Hiding a tool is not an authorization mechanism: tool calls must still be secured, and
 * they are when the tool method is protected by method security.
 * <p>
 * The current {@code Authentication} is read from the {@code SecurityContextHolder} by
 * the advisors, so this filter must run on the thread serving the request. This is the
 * case for synchronous servlet-based MCP servers, which Spring AI configures with
 * {@code immediateExecution(true)}. When no {@code Authentication} is available, secured
 * tools are hidden. Listing tools runs the advisors like a call would, so a configured
 * {@code AuthorizationEventPublisher} and {@code @HandleAuthorizationDenied} handlers are
 * also invoked while listing tools.
 *
 * @author Yongtae Choi
 */
public final class MethodSecurityMcpToolFilter implements McpSyncListFilter<McpSchema.Tool> {

	private static final Log logger = LogFactory.getLog(MethodSecurityMcpToolFilter.class);

	private static final Method PRE_AUTHORIZE_PROBE = Objects
		.requireNonNull(ReflectionUtils.findMethod(PreAuthorizeProbe.class, "probe"));

	private final McpToolMethodResolver toolMethodResolver;

	private final Map<Method, List<AuthorizationCheck>> checksByMethod = new ConcurrentHashMap<>();

	private final AtomicBoolean missingAuthenticationLogged = new AtomicBoolean();

	/**
	 * Create a filter for the tools resolved by the given resolver.
	 * @param toolMethodResolver resolves the method backing a tool from its name
	 */
	public MethodSecurityMcpToolFilter(McpToolMethodResolver toolMethodResolver) {
		Assert.notNull(toolMethodResolver, "toolMethodResolver cannot be null");
		this.toolMethodResolver = toolMethodResolver;
	}

	@Override
	public boolean isVisible(McpTransportContext transportContext, McpSchema.Tool tool) {
		McpToolMethod toolMethod = this.toolMethodResolver.resolve(tool.name());
		if (toolMethod == null) {
			return true;
		}
		List<AuthorizationCheck> checks = this.checksByMethod.computeIfAbsent(toolMethod.method(),
				(method) -> authorizationChecks(toolMethod));
		for (AuthorizationCheck check : checks) {
			if (!isGranted(check, toolMethod.method(), tool)) {
				logger.debug("Hiding tool [%s] from the tool list: access denied".formatted(tool.name()));
				return false;
			}
		}
		return true;
	}

	/**
	 * Collect the method-security advisors applying to the tool method, from the
	 * outermost proxy inwards, each with the object a call through that proxy would be
	 * invoked on.
	 */
	private static List<AuthorizationCheck> authorizationChecks(McpToolMethod toolMethod) {
		List<AuthorizationCheck> checks = new ArrayList<>();
		Class<?> targetClass = AopProxyUtils.ultimateTargetClass(toolMethod.bean());
		boolean preAuthorizeDependsOnArguments = preAuthorizeDependsOnArguments(toolMethod.method(), targetClass);
		Object proxy = toolMethod.bean();
		while (proxy instanceof Advised advised) {
			Object target = AopProxyUtils.getSingletonTarget(proxy);
			if (target == null) {
				// e.g. a scoped proxy, its target is only known at call time
				break;
			}
			for (Advisor advisor : advised.getAdvisors()) {
				AuthorizationAdvisor authorizationAdvisor = authorizationAdvisor(advisor);
				if (authorizationAdvisor != null
						&& matches(authorizationAdvisor.getPointcut(), toolMethod.method(), targetClass)) {
					boolean authorizedOnCall = preAuthorizeDependsOnArguments && matches(
							authorizationAdvisor.getPointcut(), PRE_AUTHORIZE_PROBE, PreAuthorizeProbe.class);
					checks.add(new AuthorizationCheck(authorizationAdvisor, target, authorizedOnCall));
				}
			}
			proxy = target;
		}
		return List.copyOf(checks);
	}

	/**
	 * Whether the {@link PreAuthorize @PreAuthorize} expression of the method references
	 * its arguments, or is a template whose placeholders may resolve to arguments.
	 */
	private static boolean preAuthorizeDependsOnArguments(Method method, Class<?> targetClass) {
		PreAuthorize preAuthorize = AnnotatedElementUtils.findMergedAnnotation(method, PreAuthorize.class);
		if (preAuthorize == null) {
			preAuthorize = AnnotatedElementUtils.findMergedAnnotation(targetClass, PreAuthorize.class);
		}
		return preAuthorize != null && (preAuthorize.value().contains("#") || preAuthorize.value().contains("{"));
	}

	/**
	 * Method security registers its {@link AuthorizationAdvisor}s wrapped in another
	 * advisor, which exposes the {@link AuthorizationAdvisor} as its advice.
	 */
	private static @Nullable AuthorizationAdvisor authorizationAdvisor(Advisor advisor) {
		if (advisor instanceof AuthorizationAdvisor authorizationAdvisor) {
			return authorizationAdvisor;
		}
		if (advisor instanceof PointcutAdvisor
				&& advisor.getAdvice() instanceof AuthorizationAdvisor authorizationAdvisor) {
			return authorizationAdvisor;
		}
		return null;
	}

	private static boolean matches(Pointcut pointcut, Method method, Class<?> targetClass) {
		return pointcut.getClassFilter().matches(targetClass)
				&& pointcut.getMethodMatcher().matches(method, targetClass);
	}

	private boolean isGranted(AuthorizationCheck check, Method method, McpSchema.Tool tool) {
		ListToolsInvocation invocation = new ListToolsInvocation(check.target(), method);
		try {
			check.advisor().invoke(invocation);
		}
		catch (ProceedSignal ex) {
			// the advisor let the call proceed
		}
		catch (AuthorizationDeniedException ex) {
			return check.authorizedOnCall() || dependsOnArguments(ex.getAuthorizationResult());
		}
		catch (AccessDeniedException ex) {
			return check.authorizedOnCall();
		}
		catch (AuthenticationCredentialsNotFoundException ex) {
			if (this.missingAuthenticationLogged.compareAndSet(false, true)) {
				logger.warn("No Authentication found while listing tools, hiding secured tools. "
						+ "Make sure the tool filter runs on the thread serving the request.");
			}
			return false;
		}
		catch (AuthenticationException ex) {
			return false;
		}
		catch (Throwable ex) {
			if (!invocation.proceeded) {
				logger.debug("Could not decide whether tool [%s] is authorized, it is listed".formatted(tool.name()),
						ex);
			}
			return true;
		}
		// an advisor that returns without proceeding has handled a denied invocation,
		// for example with @HandleAuthorizationDenied
		return invocation.proceeded || check.authorizedOnCall();
	}

	/**
	 * Whether a denial comes from an expression referencing the method arguments, which
	 * are {@code null} in the stand-in invocation. The expression is the one that was
	 * evaluated, after annotation templates were resolved.
	 */
	private static boolean dependsOnArguments(@Nullable Object authorizationResult) {
		return authorizationResult instanceof ExpressionAuthorizationDecision decision
				&& decision.getExpression().getExpressionString().contains("#");
	}

	/**
	 * An advisor to run against a tool method.
	 *
	 * @param advisor the advisor
	 * @param target the object a call through the advisor's proxy is invoked on
	 * @param authorizedOnCall whether the advisor's decision depends on the arguments, so
	 * that a denial while listing tools is not final
	 */
	private record AuthorizationCheck(AuthorizationAdvisor advisor, Object target, boolean authorizedOnCall) {
	}

	/**
	 * Identifies the advisors handling {@link PreAuthorize @PreAuthorize}, whose pointcut
	 * matches {@link #probe()}.
	 */
	private static final class PreAuthorizeProbe {

		@PreAuthorize("permitAll()")
		void probe() {
		}

	}

	/**
	 * A stand-in for a call to a tool method, that stops at the first {@link #proceed()}
	 * instead of invoking the tool.
	 */
	private static final class ListToolsInvocation implements MethodInvocation {

		private final Object target;

		private final Method method;

		private final @Nullable Object[] arguments;

		private boolean proceeded;

		private ListToolsInvocation(Object target, Method method) {
			this.target = target;
			this.method = method;
			this.arguments = new Object[method.getParameterCount()];
		}

		@Override
		public Method getMethod() {
			return this.method;
		}

		@Override
		public @Nullable Object[] getArguments() {
			return this.arguments;
		}

		@Override
		public Object proceed() {
			this.proceeded = true;
			throw ProceedSignal.INSTANCE;
		}

		@Override
		public Object getThis() {
			return this.target;
		}

		@Override
		public AccessibleObject getStaticPart() {
			return this.method;
		}

	}

	private static final class ProceedSignal extends RuntimeException {

		private static final ProceedSignal INSTANCE = new ProceedSignal();

		private ProceedSignal() {
			super(null, null, false, false);
		}

	}

}
