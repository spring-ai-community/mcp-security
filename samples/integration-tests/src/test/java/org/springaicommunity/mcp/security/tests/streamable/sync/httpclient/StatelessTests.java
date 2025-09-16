package org.springaicommunity.mcp.security.tests.streamable.sync.httpclient;

import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		classes = { StreamableHttpTests.StreamableHttpConfig.class }, properties = """
				mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
				mcp.server.protocol=STATELESS
				""")
class StatelessTests extends StreamableHttpTests {

}
