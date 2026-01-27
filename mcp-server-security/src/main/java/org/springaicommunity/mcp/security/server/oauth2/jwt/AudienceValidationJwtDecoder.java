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

package org.springaicommunity.mcp.security.server.oauth2.jwt;

import java.util.Collection;

import org.springaicommunity.mcp.security.server.oauth2.metadata.ResourceIdentifier;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.util.StringUtils;

/**
 * A {@link JwtDecoder} that wraps a delegate decoder and adds audience validation.
 *
 * @author Daniel Garnier-Moiroux
 */
public class AudienceValidationJwtDecoder implements JwtDecoder {

	private final JwtDecoder delegate;

	private final JwtResourceValidator validator;

	public AudienceValidationJwtDecoder(JwtDecoder delegate, ResourceIdentifier resourceIdentifier) {
		this.delegate = delegate;
		this.validator = new JwtResourceValidator(resourceIdentifier);
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		var decodedJwt = this.delegate.decode(token);
		var validationResult = this.validator.validate(decodedJwt);
		if (validationResult.hasErrors()) {
			Collection<OAuth2Error> errors = validationResult.getErrors();
			String validationErrorString = getJwtValidationExceptionMessage(errors);
			throw new JwtValidationException(validationErrorString, errors);
		}
		return decodedJwt;
	}

	private String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
		for (OAuth2Error oAuth2Error : errors) {
			if (StringUtils.hasLength(oAuth2Error.getDescription())) {
				return String.format("An error occurred while attempting to decode the Jwt: %s",
						oAuth2Error.getDescription());
			}
		}
		return "Unable to validate Jwt";
	}

}
