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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.util.Assert;

/**
 * Implementation of a {@linkGrantedAuthoritiesMapper} which does a mapping
 * based on a configured mappings between authorities.
 *
 * @author Janne Valkealahti
 */
public class MappingGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

	private Map<String, String> authoritiesMapping = new HashMap<>();

	@Override
	public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
		if (authoritiesMapping.isEmpty()) {
			return authorities;
		}
		return authorities.stream()
			.map(GrantedAuthority::getAuthority)
			.flatMap(authority -> {
				return authoritiesMapping.entrySet().stream()
					.filter(entry -> entry.getValue().equals(authority))
					.map(entry -> entry.getKey()).distinct();
			})
			.distinct()
			.map(authority -> new SimpleGrantedAuthority(authority))
			.collect(Collectors.toSet());
	}

	/**
	 * Set the mapping from resolved authorities into granted authorities.
	 *
	 * @param authoritiesMapping the authoritiesMapping to set
	 */
	public void setAuthoritiesMapping(Map<String, String> authoritiesMapping) {
		Assert.notNull(authoritiesMapping, "authoritiesMapping cannot be null");
		this.authoritiesMapping = authoritiesMapping;
	}
}
