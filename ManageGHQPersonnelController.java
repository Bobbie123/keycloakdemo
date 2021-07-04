package com.authorization.crewservice.controller;

import com.authorization.crewservice.model.UserData;
import com.authorization.crewservice.services.CustomRolePermissionEvaluator;
import com.authorization.crewservice.services.CustomUserPermissionEvaluator;
import org.keycloak.AuthorizationContext;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthorizationContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.PermissionTicketRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
//@EnableKeycloakFilter
@RequestMapping("/api/manage-ghq-personnel")
public class ManageGHQPersonnelController {

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private CustomUserPermissionEvaluator customUserPermissionEvaluator;

    @Autowired
    private CustomRolePermissionEvaluator customRolePermissionEvaluator;


    @PostMapping("/edit-personnel-details")
    //@RolesAllowed("heroes-user")
    public List<String> editPersonnelDetails() {

        KeycloakSecurityContext keycloakSecurityContext = getKeycloakSecurityContext();
        AuthorizationContext authzContext = keycloakSecurityContext.getAuthorizationContext();
        System.out.println("Authorization Context " + authzContext );


        //customKeycloakSecurityContext.setKeycloakPrincipal(((CustomKeycloakSecurityContext) keycloakSecurityContext).getKeycloakPrincipal());
        //KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal =
        //        (KeycloakPrincipal<RefreshableKeycloakSecurityContext>) request.getUserPrincipal();
        //customKeycloakSecurityContext.setKeycloakPrincipal(principal);

        ClientAuthorizationContext clientContext = ClientAuthorizationContext.class.cast(authzContext);
        //AuthzClient authzClient = clientContext.getClient();

        List<PermissionTicketRepresentation> permissions = getAuthzClient().protection().permission()
                .find("manage-ghq-personnel", "edit-personnel-details", null, getKeycloakSecurityContext().getToken().getSubject(), true, true, null, null);


        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            //throw new IllegalStateException(String.format("Went to save Keycloak account %s, but already have %s", account, authentication));
        }
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        //context.setAuthentication(new KeycloakAuthenticationToken(account, true));
        SecurityContextHolder.setContext(context);

         return Arrays.asList("1", "2");
     }

    @PostMapping("/create-mission")
    public List<String> createMission(Principal principal) {

        /*KeycloakSession session = KeycloakSession
        KeycloakIdentity keycloakIdentity = new KeycloakIdentity(KeycloakSession());*/
        System.out.println("principal "+principal);

        UserData user = new UserData();

        if (principal instanceof KeycloakPrincipal) {

            KeycloakPrincipal<KeycloakSecurityContext> kp = (KeycloakPrincipal<KeycloakSecurityContext>) principal;
            AccessToken token = kp.getKeycloakSecurityContext().getToken();
            user.setId(token.getId());
            user.setUserName(token.getName());
            Map<String, Object> otherClaims = token.getOtherClaims();
            user.setCustomAttributes(otherClaims);
        }

        KeycloakSecurityContext keycloakSecurityContext = getKeycloakSecurityContext();
        AccessToken accessToken = keycloakSecurityContext.getToken();

        AuthorizationContext authzContext = keycloakSecurityContext.getAuthorizationContext();




        ClientAuthorizationContext clientContext = ClientAuthorizationContext.class.cast(authzContext);
        //AuthzClient authzClient = clientContext.getClient();

        List<PermissionTicketRepresentation> permissions = getAuthzClient().protection().permission()
                .find(null, null, null, getKeycloakSecurityContext().getToken().getSubject(), true, true, null, null);


        customRolePermissionEvaluator.canManage();


        return Arrays.asList("Mission created");
    }

    @PostMapping("/accept-personnel-transfer")
    //@RolesAllowed("heroes-user")
    public List<String> acceptPersonnelTransfer() {

        return Arrays.asList("Accepted 1", "Accepted 2");
    }

    @PostMapping("/view-transferred-personnel")
    //@RolesAllowed("heroes-user")
    public List<String> viewTransferredPersonnel() {
        return Arrays.asList("Transferred 1", "Transferred 2");
    }

    @PostMapping("/reject-personnel-transfer")
    //@RolesAllowed("heroes-user")
    public List<String> rejectPersonnelTransfer() {
        return Arrays.asList("Rejected 1", "Rejected 2");
    }

    @PostMapping("/transfer-personnel")
    //@RolesAllowed("heroes-user")
    public List<String>transferPersonnel() {
        return Arrays.asList("Transfer 1", "Transfer 2");
    }

    private KeycloakSecurityContext getKeycloakSecurityContext() {
        return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
    }

    private AuthzClient getAuthzClient() {

        ClientAuthorizationContext clientAuthorizationContext = getAuthorizationContext();


        return getAuthorizationContext().getClient();
    }

    private ClientAuthorizationContext getAuthorizationContext() {
        return ClientAuthorizationContext.class.cast(getKeycloakSecurityContext().getAuthorizationContext());
    }

    private UserData getCustomAttributes(AccessToken accessToken){

        UserData user = new UserData();
        user.setId(accessToken.getId());
        user.setUserName(accessToken.getName());
        Map<String, Object> otherClaims = accessToken.getOtherClaims();
        user.setCustomAttributes(otherClaims);

        String id = (String) user.getCustomAttributes().get("military_id");

        return user;
    }

}

