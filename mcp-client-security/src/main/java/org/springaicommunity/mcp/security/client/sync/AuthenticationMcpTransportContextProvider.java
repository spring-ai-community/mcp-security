/*
 * Copyright 2025-2025 the original author or authors.
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

package org.springaicommunity.mcp.security.client.sync;

import java.net.http.HttpClient;
import java.util.HashMap;
import java.util.function.Supplier;

import io.modelcontextprotocol.client.transport.customizer.McpAsyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.client.transport.customizer.McpSyncHttpClientRequestCustomizer;
import io.modelcontextprotocol.common.McpTransportContext;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2AuthorizationCodeSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.http.client.OAuth2HybridSyncHttpRequestCustomizer;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2AuthorizationCodeExchangeFilterFunction;
import org.springaicommunity.mcp.security.client.sync.oauth2.webclient.McpOAuth2HybridExchangeFilterFunction;
import reactor.util.context.Context;
import reactor.util.context.ContextView;

import org.springframework.ai.model.tool.internal.ToolCallReactiveContextHolder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * A supplier that extracts security-related information from the "context", and make it
 * available to MCP clients when they send requests to MCP servers. It extracts request
 * attributes and the current authentication object. In Servlet application, this is
 * achieved with {@link SecurityContextHolder} and {@link RequestContextHolder}.
 * <p>
 * This can be used in conjunction with {@link McpSyncHttpClientRequestCustomizer} and
 * {@link McpAsyncHttpClientRequestCustomizer} for {@link HttpClient}-based transports,
 * and with {@link ExchangeFilterFunction} for {@link WebClient}-based transports.
 * <p>
 * This is usually used through a Spring AI {@code McpSyncClientCustomizer} or
 * {@code McpAsyncClientCustomizer}, like so:
 *
 * <pre>
 * &#x40;Bean
 * McpSyncClientCustomizer syncClientCustomizer() {
 *   return (name, syncSpec) -> syncSpec
 *     .transportContextProvider(
 *       new AuthenticationMcpTransportContextProvider()
 *     );
 * }
 * </pre>
 *
 * <p>
 * When using Spring's {@code ChatClient} "streaming" capabilities, you must also use
 * {@link #writeToReactorContext()} to make thread-locals available in the stream's
 * reactor context:
 *
 * <pre>
 * chatClient
 *     .prompt("your LLM prompt")
 *     .stream()
 *     .content()
 *     .contextWrite(AuthenticationMcpTransportContextProvider.writeToReactorContext())
 *     // ...
 * </pre>
 *
 * @author Daniel Garnier-Moiroux
 * @see OAuth2AuthorizationCodeSyncHttpRequestCustomizer
 * @see OAuth2HybridSyncHttpRequestCustomizer
 * @see McpOAuth2AuthorizationCodeExchangeFilterFunction
 * @see McpOAuth2HybridExchangeFilterFunction
 */
public class AuthenticationMcpTransportContextProvider implements Supplier<McpTransportContext> {

	public static final String AUTHENTICATION_KEY = Authentication.class.getName();

	public static final String REQUEST_ATTRIBUTES_KEY = RequestAttributes.class.getName();

	public static final String REACTOR_CONTEXT_KEY = "org.springaicommunity.mcp.security.client.sync.REACTOR_CONTEXT";

	private final boolean reactiveContextHolderAvailable;

	public AuthenticationMcpTransportContextProvider() {
		boolean reactiveContextHolderAvailable = false;
		try {
			Class.forName("org.springframework.ai.model.tool.internal.ToolCallReactiveContextHolder");
			reactiveContextHolderAvailable = true;
		}
		catch (ClassNotFoundException ignored) {
		}
		this.reactiveContextHolderAvailable = reactiveContextHolderAvailable;
	}

	/**
	 * Helper function to write to thread-locals to the reactor context. Use it on your
	 * reactive {@code ChatClient} operations, such as
	 * {@code chatClient.prompt("...").stream().content()}.
	 * <p>
	 * Do NOT use if Reactor is not on the classpath.
	 */
	public static ContextView writeToReactorContext() {
		return Context.empty().put(REACTOR_CONTEXT_KEY, fromThreadLocals());
	}

	/**
	 * Read authentication and request data from thread-locals. If they are not available,
	 * and a Spring AI {@code ToolCallReactiveContextHolder} is available on the
	 * classpath, it will try to access the values there.
	 */
	@Override
	public McpTransportContext get() {
		var transportContext = fromThreadLocals();

		if (this.reactiveContextHolderAvailable && transportContext == McpTransportContext.EMPTY) {
			transportContext = fromToolCallReactiveContextHolder();
		}

		return transportContext;
	}

	private static McpTransportContext fromThreadLocals() {
		var data = new HashMap<String, Object>();

		var securityContext = SecurityContextHolder.getContext();
		if (securityContext != null && securityContext.getAuthentication() != null) {
			data.put(AUTHENTICATION_KEY, securityContext.getAuthentication());
		}

		var requestAttributes = RequestContextHolder.getRequestAttributes();
		if (requestAttributes != null) {
			data.put(REQUEST_ATTRIBUTES_KEY, requestAttributes);
		}

		if (data.isEmpty()) {
			return McpTransportContext.EMPTY;
		}

		return McpTransportContext.create(data);
	}

	private static McpTransportContext fromToolCallReactiveContextHolder() {
		var reactorContext = ToolCallReactiveContextHolder.getContext();
		if (reactorContext == Context.empty()) {
			return McpTransportContext.EMPTY;
		}
		return reactorContext.getOrDefault(REACTOR_CONTEXT_KEY, McpTransportContext.EMPTY);
	}

}
