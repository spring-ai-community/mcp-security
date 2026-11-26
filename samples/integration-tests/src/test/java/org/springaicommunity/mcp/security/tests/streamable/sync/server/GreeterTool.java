package org.springaicommunity.mcp.security.tests.streamable.sync.server;

import org.springframework.ai.mcp.annotation.McpTool;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class GreeterTool {

	@McpTool(name = "greeter", description = "Greets you nicely!")
	public String greet() {
		return "Hello " + SecurityContextHolder.getContext().getAuthentication().getName();
	}

}
