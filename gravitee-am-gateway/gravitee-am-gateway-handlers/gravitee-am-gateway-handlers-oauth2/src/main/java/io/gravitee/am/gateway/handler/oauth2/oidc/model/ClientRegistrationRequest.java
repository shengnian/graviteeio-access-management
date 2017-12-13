package io.gravitee.am.gateway.handler.oauth2.oidc.model;

import java.util.ArrayList;
import java.util.List;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 *
 * See https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationRequest
 */
public class ClientRegistrationRequest {

    /**
     * redirect_uris
     *
     * REQUIRED. Array of Redirection URI values used by the Client. One of these registered Redirection URI values
     * MUST exactly match the redirect_uri parameter value used in each Authorization Request, with the matching
     * performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
     */
    private List<String> redirectUris = new ArrayList<>();

    /**
     * response_types
     *
     * OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that the Client is declaring that
     * it will restrict itself to using. If omitted, the default is that the Client will use only the code Response Type.
     */
    private List<String> responseTypes = new ArrayList<>();

    /**
     * grant_types
     *
     * OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Types that the Client is declaring that it will
     * restrict itself to using.
     */
    private List<String> grantTypes = new ArrayList<>();

    /**
     * application_type
     *
     * OPTIONAL. Kind of the application. The default, if omitted, is web. The defined values are native or web. Web
     * Clients using the OAuth Implicit Grant Type MUST only register URLs using the https scheme as redirect_uris;
     * they MUST NOT use localhost as the hostname. Native Clients MUST only register redirect_uris using custom URI
     * schemes or URLs using the http: scheme with localhost as the hostname. Authorization Servers MAY place additional
     * constraints on Native Clients. Authorization Servers MAY reject Redirection URI values using the http scheme,
     * other than the localhost case for Native Clients. The Authorization Server MUST verify that all the registered
     * redirect_uris conform to these constraints. This prevents sharing a Client ID across different types of Clients.
     */
    private ApplicationType applicationType;

    /**
     * contacts
     *
     * OPTIONAL. Array of e-mail addresses of people responsible for this Client. This might be used by some providers
     * to enable a Web user interface to modify the Client information.
     */
    private List<String> contacts = new ArrayList<>();

    /**
     * client_name
     *
     * OPTIONAL. Name of the Client to be presented to the End-User. If desired, representation of this Claim in
     * different languages and scripts is represented as described in Section 2.1.
     */
    private String clientName;

    /**
     * logo_uri
     *
     * OPTIONAL. URL that references a logo for the Client application. If present, the server SHOULD display this
     * image to the End-User during approval. The value of this field MUST point to a valid image file. If desired,
     * representation of this Claim in different languages and scripts is represented as described in Section 2.1.
     *
     */
    private String logoUri;

    /**
     * client_uri
     *
     * OPTIONAL. URL of the home page of the Client. The value of this field MUST point to a valid Web page. If present,
     * the server SHOULD display this URL to the End-User in a followable fashion. If desired, representation of this
     * Claim in different languages and scripts is represented as described in Section 2.1.
     *
     */
    private String clientUri;

    /**
     * policy_uri
     *
     * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the how the profile data will
     * be used. The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display this URL to
     * the End-User if it is given. If desired, representation of this Claim in different languages and scripts is
     * represented as described in Section 2.1.
     *
     */
    private String policyUri;

    /**
     * tos_uri
     *
     * OPTIONAL. URL that the Relying Party Client provides to the End-User to read about the Relying Party's terms of
     * service. The value of this field MUST point to a valid web page. The OpenID Provider SHOULD display this URL to
     * the End-User if it is given. If desired, representation of this Claim in different languages and scripts is
     * represented as described in Section 2.1.
     */
    private String tosUri;

    /**
     * jwks_uri
     *
     * OPTIONAL. URL for the Client's JSON Web Key Set [JWK] document. If the Client signs requests to the Server, it
     * contains the signing key(s) the Server uses to validate signatures from the Client. The JWK Set MAY also contain
     * the Client's encryption keys(s), which are used by the Server to encrypt responses to the Client. When both
     * signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the
     * referenced JWK Set to indicate each key's intended usage. Although some algorithms allow the same key to be
     * used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter
     * MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be
     * present and MUST match those in the certificate.
     */
    private String jwksUri;

    /**
     * jwks
     *
     * OPTIONAL. Client's JSON Web Key Set [JWK] document, passed by value. The semantics of the jwks parameter are the
     * same as the jwks_uri parameter, other than that the JWK Set is passed by value, rather than by reference. This
     * parameter is intended only to be used by Clients that, for some reason, are unable to use the jwks_uri parameter,
     * for instance, by native applications that might not have a location to host the contents of the JWK Set. If a
     * Client can use jwks_uri, it MUST NOT use jwks. One significant downside of jwks is that it does not enable key
     * rotation (which jwks_uri does, as described in Section 10 of OpenID Connect Core 1.0 [OpenID.Core]). The jwks_uri
     * and jwks parameters MUST NOT be used together.
     */
    private String jwks;

    /**
     * sector_identifier_uri
     *
     * OPTIONAL. URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL
     * references a file with a single JSON array of redirect_uri values. Please see Section 5. Providers that use
     * pairwise sub (subject) values SHOULD utilize the sector_identifier_uri value provided in the Subject Identifier
     * calculation for pairwise identifiers.
     */
    private String sectorIdentifierUri;

    /**
     * subject_type
     *
     * OPTIONAL. subject_type requested for responses to this Client. The subject_types_supported Discovery parameter
     * contains a list of the supported subject_type values for this server. Valid types include pairwise and public.
     */
    private SubjectType subjectType;

    /**
     * id_token_signed_response_alg
     *
     * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. The value none MUST
     * NOT be used as the ID Token alg value unless the Client uses only Response Types that return no ID Token from the
     * Authorization Endpoint (such as when only using the Authorization Code Flow). The default, if omitted, is RS256.
     * The public key for validating the signature is provided by retrieving the JWK Set referenced by the jwks_uri
     * element from OpenID Connect Discovery 1.0 [OpenID.Discovery].
     */
    private String idTokenSignedResponseAlg;

    /**
     * id_token_encrypted_response_alg
     *
     * OPTIONAL. JWE alg algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If this is
     * requested, the response will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT].
     * The default, if omitted, is that no encryption is performed.
     */
    private String idTokenEncryptedResponseAlg;

    /**
     * id_token_encrypted_response_enc
     *
     * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting the ID Token issued to this Client. If
     * id_token_encrypted_response_alg is specified, the default for this value is A128CBC-HS256. When
     * id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided.
     */
    private String idTokenEncryptedResponseEnc;

    /**
     * userinfo_signed_response_alg
     *
     * OPTIONAL. JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the response
     * will be JWT [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to
     * return the Claims as a UTF-8 encoded JSON object using the application/json content-type.
     */
    private String userInfoSignedResponseAlg;

    /**
     * userinfo_encrypted_response_alg
     *
     * OPTIONAL. JWE [JWE] alg algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If both signing and
     * encryption are requested, the response will be signed then encrypted, with the result being a Nested JWT, as
     * defined in [JWT]. The default, if omitted, is that no encryption is performed.
     */
    private String userInfoEncryptedResponseAlg;

    /**
     * userinfo_encrypted_response_enc
     *
     * OPTIONAL. JWE enc algorithm [JWA] REQUIRED for encrypting UserInfo Responses. If userinfo_encrypted_response_alg
     * is specified, the default for this value is A128CBC-HS256. When userinfo_encrypted_response_enc is included,
     * userinfo_encrypted_response_alg MUST also be provided.
     */
    private String userInfoEncryptedResponseEnc;

    /**
     * request_object_signing_alg
     *
     * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request
     * Objects from this Client MUST be rejected, if not signed with this algorithm. Request Objects are described in
     * Section 6.1 of OpenID Connect Core 1.0 [OpenID.Core]. This algorithm MUST be used both when the Request Object
     * is passed by value (using the request parameter) and when it is passed by reference (using the request_uri
     * parameter). Servers SHOULD support RS256. The value none MAY be used. The default, if omitted, is that any
     * algorithm supported by the OP and the RP MAY be used.
     */
    private String requestObjectSigningAlg;

    /**
     * request_object_encryption_alg
     *
     * OPTIONAL. JWE [JWE] alg algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent
     * to the OP. This parameter SHOULD be included when symmetric encryption will be used, since this signals to the
     * OP that a client_secret value needs to be returned from which the symmetric key will be derived, that might not
     * otherwise be returned. The RP MAY still use other supported encryption algorithms or send unencrypted Request
     * Objects, even when this parameter is present. If both signing and encryption are requested, the Request Object
     * will be signed then encrypted, with the result being a Nested JWT, as defined in [JWT]. The default, if omitted,
     * is that the RP is not declaring whether it might encrypt any Request Objects.
     */
    private String requestObjectEncryptionAlg;

    /**
     * request_object_encryption_enc
     *
     * OPTIONAL. JWE enc algorithm [JWA] the RP is declaring that it may use for encrypting Request Objects sent to the
     * OP. If request_object_encryption_alg is specified, the default for this value is A128CBC-HS256. When
     * request_object_encryption_enc is included, request_object_encryption_alg MUST also be provided.
     */
    private String requestObjectEncryptionEnc;

    /**
     * token_endpoint_auth_method
     *
     * OPTIONAL. Requested Client Authentication method for the Token Endpoint. The options are client_secret_post,
     * client_secret_basic, client_secret_jwt, private_key_jwt, and none, as described in Section 9 of OpenID Connect
     * Core 1.0 [OpenID.Core]. Other authentication methods MAY be defined by extensions. If omitted, the default is
     * client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
     */
    private TokenEndpointAuthMethod tokenEndpointAuthMethod = TokenEndpointAuthMethod.CLIENT_SECRET_BASIC;

    /**
     * token_endpoint_auth_signing_alg
     *
     * OPTIONAL. JWS [JWS] alg algorithm [JWA] that MUST be used for signing the JWT [JWT] used to authenticate the
     * Client at the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods. All Token
     * Requests using these authentication methods from this Client MUST be rejected, if the JWT is not signed with
     * this algorithm. Servers SHOULD support RS256. The value none MUST NOT be used. The default, if omitted, is that
     * any algorithm supported by the OP and the RP MAY be used.
     */
    private String tokenEndpointAuthSigningAlg;

    /**
     * default_max_age
     *
     * OPTIONAL. Default Maximum Authentication Age. Specifies that the End-User MUST be actively authenticated if the
     * End-User was authenticated longer ago than the specified number of seconds. The max_age request parameter
     * overrides this default value. If omitted, no default Maximum Authentication Age is specified.
     */
    private int defaultMaxAge = -1;

    /**
     * require_auth_time
     *
     * OPTIONAL. Boolean value specifying whether the auth_time Claim in the ID Token is REQUIRED. It is REQUIRED when
     * the value is true. (If this is false, the auth_time Claim can still be dynamically requested as an individual
     * Claim for the ID Token using the claims request parameter described in Section 5.5.1 of OpenID Connect Core 1.0
     * [OpenID.Core].) If omitted, the default value is false.
     */
    private boolean requireAuthTime;

    /**
     * default_acr_values
     *
     * OPTIONAL. Default requested Authentication Context Class Reference values. Array of strings that specifies the
     * default acr values that the OP is being requested to use for processing requests from this Client, with the
     * values appearing in order of preference. The Authentication Context Class satisfied by the authentication
     * performed is returned as the acr Claim Value in the issued ID Token. The acr Claim is requested as a Voluntary
     * Claim by this parameter. The acr_values_supported discovery element contains a list of the supported acr values
     * supported by this server. Values specified in the acr_values request parameter or an individual acr Claim request
     * override these default values.
     */
    private String defaultAcrValues;

    /**
     * initiate_login_uri
     *
     * OPTIONAL. URI using the https scheme that a third party can use to initiate a login by the RP, as specified in
     * Section 4 of OpenID Connect Core 1.0 [OpenID.Core]. The URI MUST accept requests via both GET and POST. The
     * Client MUST understand the login_hint and iss parameters and SHOULD support the target_link_uri parameter.
     */
    private String initiateLoginUri;

    /**
     * request_uris
     *
     * OPTIONAL. Array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY cache the
     * contents of the files referenced by these URIs and not retrieve them at the time they are used in a request. OPs
     * can require that request_uri values used be pre-registered with the require_request_uri_registration discovery
     * parameter.
     * If the contents of the request file could ever change, these URI values SHOULD include the base64url encoded
     * SHA-256 hash value of the file contents referenced by the URI as the value of the URI fragment. If the fragment
     * value used for a URI changes, that signals the server that its cached value for that URI with the old fragment
     * value is no longer valid.
     */
    private List<String> requestUris = new ArrayList<>();

    public List<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(List<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public List<String> getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(List<String> responseTypes) {
        this.responseTypes = responseTypes;
    }

    public List<String> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(List<String> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public ApplicationType getApplicationType() {
        return applicationType;
    }

    public void setApplicationType(ApplicationType applicationType) {
        this.applicationType = applicationType;
    }

    public List<String> getContacts() {
        return contacts;
    }

    public void setContacts(List<String> contacts) {
        this.contacts = contacts;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public String getLogoUri() {
        return logoUri;
    }

    public void setLogoUri(String logoUri) {
        this.logoUri = logoUri;
    }

    public String getClientUri() {
        return clientUri;
    }

    public void setClientUri(String clientUri) {
        this.clientUri = clientUri;
    }

    public String getPolicyUri() {
        return policyUri;
    }

    public void setPolicyUri(String policyUri) {
        this.policyUri = policyUri;
    }

    public String getTosUri() {
        return tosUri;
    }

    public void setTosUri(String tosUri) {
        this.tosUri = tosUri;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getJwks() {
        return jwks;
    }

    public void setJwks(String jwks) {
        this.jwks = jwks;
    }

    public String getSectorIdentifierUri() {
        return sectorIdentifierUri;
    }

    public void setSectorIdentifierUri(String sectorIdentifierUri) {
        this.sectorIdentifierUri = sectorIdentifierUri;
    }

    public SubjectType getSubjectType() {
        return subjectType;
    }

    public void setSubjectType(SubjectType subjectType) {
        this.subjectType = subjectType;
    }

    public String getIdTokenSignedResponseAlg() {
        return idTokenSignedResponseAlg;
    }

    public void setIdTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
    }

    public String getIdTokenEncryptedResponseAlg() {
        return idTokenEncryptedResponseAlg;
    }

    public void setIdTokenEncryptedResponseAlg(String idTokenEncryptedResponseAlg) {
        this.idTokenEncryptedResponseAlg = idTokenEncryptedResponseAlg;
    }

    public String getIdTokenEncryptedResponseEnc() {
        return idTokenEncryptedResponseEnc;
    }

    public void setIdTokenEncryptedResponseEnc(String idTokenEncryptedResponseEnc) {
        this.idTokenEncryptedResponseEnc = idTokenEncryptedResponseEnc;
    }

    public String getUserInfoSignedResponseAlg() {
        return userInfoSignedResponseAlg;
    }

    public void setUserInfoSignedResponseAlg(String userInfoSignedResponseAlg) {
        this.userInfoSignedResponseAlg = userInfoSignedResponseAlg;
    }

    public String getUserInfoEncryptedResponseAlg() {
        return userInfoEncryptedResponseAlg;
    }

    public void setUserInfoEncryptedResponseAlg(String userInfoEncryptedResponseAlg) {
        this.userInfoEncryptedResponseAlg = userInfoEncryptedResponseAlg;
    }

    public String getUserInfoEncryptedResponseEnc() {
        return userInfoEncryptedResponseEnc;
    }

    public void setUserInfoEncryptedResponseEnc(String userInfoEncryptedResponseEnc) {
        this.userInfoEncryptedResponseEnc = userInfoEncryptedResponseEnc;
    }

    public String getRequestObjectSigningAlg() {
        return requestObjectSigningAlg;
    }

    public void setRequestObjectSigningAlg(String requestObjectSigningAlg) {
        this.requestObjectSigningAlg = requestObjectSigningAlg;
    }

    public String getRequestObjectEncryptionAlg() {
        return requestObjectEncryptionAlg;
    }

    public void setRequestObjectEncryptionAlg(String requestObjectEncryptionAlg) {
        this.requestObjectEncryptionAlg = requestObjectEncryptionAlg;
    }

    public String getRequestObjectEncryptionEnc() {
        return requestObjectEncryptionEnc;
    }

    public void setRequestObjectEncryptionEnc(String requestObjectEncryptionEnc) {
        this.requestObjectEncryptionEnc = requestObjectEncryptionEnc;
    }

    public TokenEndpointAuthMethod getTokenEndpointAuthMethod() {
        return tokenEndpointAuthMethod;
    }

    public void setTokenEndpointAuthMethod(TokenEndpointAuthMethod tokenEndpointAuthMethod) {
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public String getTokenEndpointAuthSigningAlg() {
        return tokenEndpointAuthSigningAlg;
    }

    public void setTokenEndpointAuthSigningAlg(String tokenEndpointAuthSigningAlg) {
        this.tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg;
    }

    public int getDefaultMaxAge() {
        return defaultMaxAge;
    }

    public void setDefaultMaxAge(int defaultMaxAge) {
        this.defaultMaxAge = defaultMaxAge;
    }

    public boolean isRequireAuthTime() {
        return requireAuthTime;
    }

    public void setRequireAuthTime(boolean requireAuthTime) {
        this.requireAuthTime = requireAuthTime;
    }

    public String getDefaultAcrValues() {
        return defaultAcrValues;
    }

    public void setDefaultAcrValues(String defaultAcrValues) {
        this.defaultAcrValues = defaultAcrValues;
    }

    public String getInitiateLoginUri() {
        return initiateLoginUri;
    }

    public void setInitiateLoginUri(String initiateLoginUri) {
        this.initiateLoginUri = initiateLoginUri;
    }

    public List<String> getRequestUris() {
        return requestUris;
    }

    public void setRequestUris(List<String> requestUris) {
        this.requestUris = requestUris;
    }

    public enum ApplicationType {
        WEB("web"),
        NATIVE("native");

        private final String name;

        ApplicationType(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public enum SubjectType {
        PAIRWISE("pairwise"),
        PUBLIC("public");

        private final String name;

        SubjectType(final String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }

    public enum TokenEndpointAuthMethod {
        CLIENT_SECRET_POST("client_secret_post"),
        CLIENT_SECRET_BASIC("client_secret_basic"),
        CLIENT_SECRET_JWT("client_secret_jwt"),
        PRIVATE_KEY_JWT("private_key_jwt"),
        NONE("none");

        private final String name;

        TokenEndpointAuthMethod(final String name) {
            this.name = name;
        }
    }
}
