package com.dataiku.customauth;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.openapitools.client.ApiClient;
import org.openapitools.client.ApiException;
import org.openapitools.client.api.GroupApi;
import org.openapitools.client.api.UserApi;
import org.openapitools.client.model.Group;

import com.dataiku.dip.security.auth.ServerAuthenticationFailure;
import com.dataiku.dip.security.auth.UserAttributes;
import com.dataiku.dip.security.auth.UserIdentity;
import com.dataiku.dip.security.auth.UserNotFoundException;
import com.dataiku.dip.security.auth.UserQueryFilter;
import com.dataiku.dip.security.custom.CustomUserSupplier;
import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.AuthorizationMode;
import com.okta.sdk.client.Clients;

/**
 * Supply a user from an external user store into DSS.
 * This supplier needs to fetch the user from the external store using the user attribute resulting from the authentication in DSS and then map
 * the user into a DSS user attribute, in order to sync or provisioning it if needed.
 */
public class OktaCustomUserSupplier implements CustomUserSupplier {
    private final GroupApi groupApi;
    private final  UserApi userApi;

    public OktaCustomUserSupplier() {
        String OKTA_API_KEY = System.getenv("OKTA_API_KEY");
        String OKTA_ORG_URL = System.getenv("OKTA_ORG_URL");
        TokenClientCredentials tokenClientCredentials = new TokenClientCredentials(OKTA_API_KEY);
        ApiClient apiClient = Clients.builder()
                .setAuthorizationMode(AuthorizationMode.SSWS)
                .setOrgUrl(OKTA_ORG_URL)
                .setClientCredentials(tokenClientCredentials)
                .build();
        userApi = new UserApi(apiClient);
        groupApi = new GroupApi(apiClient);
    }
    
    /**
     * Read the user from the source into user attributes.
     * Note: The user attributes can be use for either sync or provision, depending on if a user in DSS already exist.
     * The user supplier is not directly in charge of saving the user in DSS.
     * @param userIdentity The user identity issued from the authentication.
     * @return The external user mapped into a DSS user attributes.
     * @throws ServerAuthenticationFailure if an unexpected error occurs
     * @throws UserNotFoundException if no user in the external user source matches the user identity.
     */
    @Override
    public UserAttributes getUserAttributes(UserIdentity userIdentity) throws ServerAuthenticationFailure, UserNotFoundException {
        try {
            return userApi.listUsers(null, null, 5, "profile.email eq \"" + userIdentity.login + "@dataiku.com\"", null, null, null)
                    .stream()
                    .findAny()
                    .map(oktaUser -> {
                        UserAttributes userAttributes = new UserAttributes();
                        userAttributes.login = oktaUser.getProfile().getLogin();
                        userAttributes.email = oktaUser.getProfile().getEmail();
                        userAttributes.displayName = oktaUser.getProfile().getDisplayName();
                        try {
                            List<Group> groups = userApi.listUserGroups(oktaUser.getId());
                            userAttributes.sourceGroupNames = groups.stream().map(g -> g.getProfile().getName()).collect(Collectors.toSet());
                        } catch (ApiException e) {
                            throw new RuntimeException(e);
                        }
                        return userAttributes;
                    })
                    .orElseThrow(() -> new UserNotFoundException("Couldn't find user '" + userIdentity.login + "'"));
        } catch (ApiException e) {
            throw new ServerAuthenticationFailure("An issue on the OKTA api", e);
        }
    }

    /**
     * Fetch users from the source into user attributes.
     * This method is used to display users from this source through the admin UI or the public API.
     * The user supplier is not directly in charge of saving the user in DSS.
     * @param filter filters that must be applied on this source users
     * @return a set of external users who match the provided filters of all users if the filters are empty
     * @throws ServerAuthenticationFailure if an unexpected error occurs
     */
    @Override
    public Set<UserAttributes> fetchUsers(UserQueryFilter filter) throws ServerAuthenticationFailure {
        String oktaFilter = null;

        if (filter.getLogin() != null) {
            oktaFilter = "profile.email eq \"" + filter.getLogin() + "@dataiku.com\"";
        }
        try {
            return userApi.listUsers(null, null, null, oktaFilter, null, null, null)
                    .stream()
                    .map(oktaUser -> {
                        UserAttributes userAttributes = new UserAttributes();
                        userAttributes.login = oktaUser.getProfile().getLogin();
                        userAttributes.email = oktaUser.getProfile().getEmail();
                        userAttributes.displayName = oktaUser.getProfile().getDisplayName();
                        try {
                            List<Group> groups = userApi.listUserGroups(oktaUser.getId());
                            userAttributes.sourceGroupNames = groups.stream().map(g -> g.getProfile().getName()).collect(Collectors.toSet());
                        } catch (ApiException e) {
                            throw new RuntimeException(e);
                        }
                        return userAttributes;
                    })
                    .filter(u -> {
                        if (filter.getGroupName() != null) {
                            return u.sourceGroupNames != null && u.sourceGroupNames.contains(filter.getGroupName());
                        }
                        return true;
                    })
                    .collect(Collectors.toSet());
        } catch (ApiException e) {
            throw new ServerAuthenticationFailure("An issue on the OKTA api", e);
        }
    }

    /**
     * Fetch groups from the source.
     * This method is used to display groups from this source through the admin UI or the public API.
     * @return a set of external group names
     * @throws ServerAuthenticationFailure if an unexpected error occurs
     */
    @Override
    public Set<String> fetchGroups() throws ServerAuthenticationFailure {
        // fetch groups
        try {
            return groupApi.listGroups(null, null, null, null, null, null, null, null, Collections.emptyMap())
                    .stream().map(g -> g.getProfile().getName()).collect(Collectors.toSet());
        } catch (ApiException e) {
            throw new ServerAuthenticationFailure("An issue on the OKTA api", e);
        }
    }

    /**
     * Whether the user supplier is *able* to sync users on demand (i.e. not during login process)
     */
    @Override
    public boolean canSyncOnDemand() {
        return true;
    }

    /**
     * Whether the user supplier is *able* to fetch users using filters
     */
    @Override
    public boolean canFetchUsers() {
        return true;
    }

    /**
     * Whether the user supplier is *able* to fetch groups
     */
    @Override
    public boolean canFetchGroups() {
        return true;
    }
}
