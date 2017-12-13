package io.gravitee.am.gateway.handler.oauth2.oidc.endpoint;

import io.gravitee.am.gateway.handler.oauth2.oidc.model.ClientRegistrationRequest;
import io.gravitee.am.gateway.handler.oauth2.oidc.model.ClientRegistrationResponse;
import io.gravitee.am.gateway.service.ClientService;
import io.gravitee.am.model.Domain;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Controller
@RequestMapping("register")
public class DynamicClientRegistrationEndpoint {

    @Autowired
    private Domain domain;

    @Autowired
    private ClientService clientService;

    @RequestMapping(
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationResponse registerClient(@RequestBody ClientRegistrationRequest clientRegistration) {

        // Set default values
        if (clientRegistration.getTokenEndpointAuthMethod() == null) {
            clientRegistration.setTokenEndpointAuthMethod(ClientRegistrationRequest.TokenEndpointAuthMethod.CLIENT_SECRET_BASIC);
        }

        clientService.create(domain.getId(), clientRegistration);

        return new ClientRegistrationResponse();
    }
}
