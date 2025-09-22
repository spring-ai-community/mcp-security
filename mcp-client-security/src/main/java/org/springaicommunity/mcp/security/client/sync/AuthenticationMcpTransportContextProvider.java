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

import io.modelcontextprotocol.common.McpTransportContext;
import java.util.HashMap;
import java.util.function.Supplier;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * @author Daniel Garnier-Moiroux
 */
public class AuthenticationMcpTransportContextProvider implements Supplier<McpTransportContext> {

	public static final String AUTHENTICATION_KEY = Authentication.class.getName();

	public static final String REQUEST_ATTRIBUTES_KEY = RequestAttributes.class.getName();

	@Override
	public McpTransportContext get() {
		var data = new HashMap<String, Object>();

		var securityContext = SecurityContextHolder.getContext();
		if (securityContext != null && securityContext.getAuthentication() != null) {
			data.put(AUTHENTICATION_KEY, securityContext.getAuthentication());
		}

		var requestAttributes = RequestContextHolder.getRequestAttributes();
		if (requestAttributes != null) {
			data.put(REQUEST_ATTRIBUTES_KEY, requestAttributes);
		}

		return McpTransportContext.create(data);
	}

}
