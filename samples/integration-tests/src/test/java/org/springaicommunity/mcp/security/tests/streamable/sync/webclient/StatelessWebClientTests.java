package org.springaicommunity.mcp.security.tests.streamable.sync.webclient;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		classes = StatelessWebClientTests.StreamableHttpConfig.class, properties = """
				mcp.server.class=org.springaicommunity.mcp.security.tests.streamable.sync.server.StreamableHttpMcpServer
				mcp.server.protocol=STATELESS
				""")
@ActiveProfiles("sync")
class StatelessWebClientTests extends StreamableHttpWebClientTests {

}
