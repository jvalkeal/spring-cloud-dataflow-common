/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.cloud.dataflow.common.security.support;

import java.util.Collections;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.cloud.dataflow.common.security.support.ConditionalOnIdentityProvider.Type;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * {@link Condition} that checks if a spesific identity provider is defined in environment.
 *
 * @author Janne Valkealahti
 */
public class OnIdentityProviderCondition extends SpringBootCondition {

	@Override
	public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
		return isIdentityProvider(context, metadata);
	}

	private ConditionOutcome isIdentityProvider(ConditionContext context, AnnotatedTypeMetadata metadata) {
		switch (deduceType(metadata)) {
		case AZUREAD:
			return isAADIdentityProvider(context);
		case LEGACY:
			return isLegacyIdentityProvider(context);
		default:
			return isNoneIdentityProvider(context);
		}
	}

	private ConditionOutcome isAADIdentityProvider(ConditionContext context) {
		Environment environment = context.getEnvironment();
		boolean hasTenantId = environment.containsProperty("azure.activedirectory.tenant-id");
		if (hasTenantId) {
			return ConditionOutcome.match(ConditionMessage.forCondition(ConditionalOnIdentityProvider.class)
					.found("property").items("azure.activedirectory.tenant-id"));
		} {
			return ConditionOutcome.noMatch(ConditionMessage.forCondition(ConditionalOnIdentityProvider.class)
					.didNotFind("property").items("azure.activedirectory.tenant-id"));
		}
	}

	private ConditionOutcome isLegacyIdentityProvider(ConditionContext context) {
		Environment environment = context.getEnvironment();
		boolean hasTenantId = environment.containsProperty("azure.activedirectory.tenant-id");
		Map<String, String> properties = getSubProperties(context.getEnvironment(), "spring.security.oauth2");
		if (hasTenantId) {
			return ConditionOutcome.noMatch(ConditionMessage.forCondition(ConditionalOnIdentityProvider.class)
					.found("azure.activedirectory.tenant-id").items());
		}
		else if (properties.isEmpty()) {
			return ConditionOutcome.noMatch(ConditionMessage.forCondition(ConditionalOnIdentityProvider.class)
					.didNotFind("spring.security.oauth2").atAll());
		}
		else {
			return ConditionOutcome.match(ConditionMessage.forCondition(ConditionalOnIdentityProvider.class)
					.found("spring.security.oauth2").items(properties.keySet()));
		}
	}

	private ConditionOutcome isNoneIdentityProvider(ConditionContext context) {
		return ConditionOutcome.match(ConditionMessage.of("No supported security properties found"));
	}

	private Type deduceType(AnnotatedTypeMetadata metadata) {
		Map<String, Object> attributes = metadata.getAnnotationAttributes(ConditionalOnIdentityProvider.class.getName());
		if (attributes != null) {
			return (Type) attributes.get("type");
		}
		return Type.NONE;
	}

	private static Map<String, String> getSubProperties(Environment environment, String keyPrefix) {
		return Binder.get(environment)
			.bind(keyPrefix, Bindable.mapOf(String.class, String.class))
			.orElseGet(Collections::emptyMap);
	}
}
