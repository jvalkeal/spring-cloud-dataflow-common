/*
 * Copyright 2019-2020 the original author or authors.
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
package org.springframework.cloud.dataflow.common.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Holds configuration for the authorization aspects of security.
 *
 * @author Gunnar Hillert
 * @author Janne Valkealahti
 *
 */
public class ProviderRoleMapping {

	private String oauthScopePrefix = "dataflow.";
	private String rolePrefix = "ROLE_";

	private boolean mapOauthScopes = false;

	private Map<String, String> roleMappings = new HashMap<>(0);

	public ProviderRoleMapping() {
		super();
	}

	public ProviderRoleMapping(boolean mapOauthScopes) {
		this.mapOauthScopes = mapOauthScopes;
	}

	public ProviderRoleMapping(boolean mapOauthScopes, Map<String, String> roleMappings) {
		Assert.notNull(roleMappings, "roleMappings must not be null.");
		this.mapOauthScopes = mapOauthScopes;
		this.roleMappings = roleMappings;
	}

	public boolean isMapOauthScopes() {
		return mapOauthScopes;
	}

	/**
	 * If set to true, Oauth scopes will be mapped to corresponding Data Flow roles.
	 * Otherwise, if set to false, or not set at all, all roles will be assigned to users.
	 *
	 * @param mapOauthScopes If not set defaults to false
	 */
	public void setMapOauthScopes(boolean mapOauthScopes) {
		this.mapOauthScopes = mapOauthScopes;
	}

	/**
	 * When using OAuth2 with enabled {@link #setMapOauthScopes(boolean)}, you can optionally specify a custom
	 * mapping of OAuth scopes to role names as they exist in the Data Flow application. If not
	 * set, then the OAuth scopes themselves must match the role names:
	 *
	 * <ul>
	 *   <li>MANAGE = dataflow.manage
	 *   <li>VIEW = dataflow.view
	 *   <li>CREATE = dataflow.create
	 * </ul>
	 *
	 * @return Optional (May be null). Returns a map of scope-to-role mappings.
	 */
	public Map<String, String> getRoleMappings() {
		return roleMappings;
	}

	public ProviderRoleMapping addRoleMapping(String oauthScope, String roleName)  {
		this.roleMappings.put(oauthScope, roleName);
		return this;
	}
	/**
	 * @return Map containing the {@link CoreSecurityRoles} as key and the associated role name (String) as value.
	 */
	public Map<CoreSecurityRoles, String> convertRoleMappingKeysToCoreSecurityRoles() {

		final Map<CoreSecurityRoles, String> roleMappings = new HashMap<>(0);

		if (CollectionUtils.isEmpty(this.roleMappings)) {
			for (CoreSecurityRoles roleEnum : CoreSecurityRoles.values()) {
				final String roleName = this.oauthScopePrefix + roleEnum.getKey();
				roleMappings.put(roleEnum, roleName);
			}
			return roleMappings;
		}

		final List<CoreSecurityRoles> unmappedRoles = new ArrayList<>(0);

		for (CoreSecurityRoles coreRole : CoreSecurityRoles.values()) {

			final String coreSecurityRoleName;
			if (this.rolePrefix.length() > 0 && !coreRole.getKey().startsWith(rolePrefix)) {
				coreSecurityRoleName = rolePrefix + coreRole.getKey();
			}
			else {
				coreSecurityRoleName = coreRole.getKey();
			}

			final String oauthScope = this.roleMappings.get(coreSecurityRoleName);

			if (oauthScope == null) {
				unmappedRoles.add(coreRole);
			}
			else {
				roleMappings.put(coreRole, oauthScope);
			}
		}

		if (!unmappedRoles.isEmpty()) {
			throw new IllegalArgumentException(
				String.format("The following %s %s not mapped: %s.",
					unmappedRoles.size(),
					unmappedRoles.size() > 1 ? "roles are" : "role is",
					StringUtils.collectionToDelimitedString(unmappedRoles, ", ")));
		}

		return roleMappings;
	}

	/**
	 * Sets the prefix which should be added to the authority name (if it doesn't already
	 * exist).
	 *
	 * @param rolePrefix Must not be null
	 *
	 */
	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "rolePrefix cannot be null");
		this.rolePrefix = rolePrefix;
	}

	public String getOauthScopePrefix() {
		return oauthScopePrefix;
	}

	/**
	 *
	 * @param oauthScopePrefix Must not be null
	 */
	public void setOauthScopePrefix(String oauthScopePrefix) {
		Assert.notNull(rolePrefix, "oauthScopePrefix cannot be null");
		this.oauthScopePrefix = oauthScopePrefix;
	}

	public String getRolePrefix() {
		return rolePrefix;
	}
}
