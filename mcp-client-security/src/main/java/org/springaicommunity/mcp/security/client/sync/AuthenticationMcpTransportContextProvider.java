package org.springaicommunity.mcp.security.client.sync;

import io.modelcontextprotocol.common.McpTransportContext;
import java.util.HashMap;
import java.util.function.Supplier;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

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
