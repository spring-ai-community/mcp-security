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

package org.springaicommunity.mcp.security.common.url;

/**
 * Exception thrown when a URL fails validation.
 */
public class InvalidUrlException extends Exception {

	private final String url;

	public InvalidUrlException(String message, String url) {
		super(message);
		this.url = url;
	}

	public InvalidUrlException(String message, String url, Throwable cause) {
		super(message, cause);
		this.url = url;
	}

	public String getUrl() {
		return url;
	}

}
