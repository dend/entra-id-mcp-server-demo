import express, { RequestHandler } from "express";
import { clientRegistrationHandler, ClientRegistrationHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/register.js";
import { TokenHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/token.js";
import { authorizationHandler, AuthorizationHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/authorize.js";
import { revocationHandler, RevocationHandlerOptions } from "@modelcontextprotocol/sdk/server/auth/handlers/revoke.js";
import { metadataHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/metadata.js";
import { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { entraIdTokenHandler } from "./EntraIdTokenHandler.js";

export type AuthRouterOptions = {
    /**
     * A provider implementing the actual authorization logic for this router.
     */
    provider: OAuthServerProvider;

    /**
     * The authorization server's issuer identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
     */
    issuerUrl: URL;

    /**
     * An optional URL of a page containing human-readable information that developers might want or need to know when using the authorization server.
     */
    serviceDocumentationUrl?: URL;

    // Individual options per route
    authorizationOptions?: Omit<AuthorizationHandlerOptions, "provider">;
    clientRegistrationOptions?: Omit<ClientRegistrationHandlerOptions, "clientsStore">;
    revocationOptions?: Omit<RevocationHandlerOptions, "provider">;
    tokenOptions?: Omit<TokenHandlerOptions, "provider">;
};

/**
 * Installs standard MCP authorization endpoints, including dynamic client registration and token revocation (if supported). Also advertises standard authorization server metadata, for easier discovery of supported configurations by clients.
 * 
 * By default, rate limiting is applied to all endpoints to prevent abuse.
 * 
 * This router MUST be installed at the application root, like so:
 * 
 *  const app = express();
 *  app.use(mcpAuthRouter(...));
 */
export function entraIdAuthRouter(options: AuthRouterOptions): RequestHandler {
    const issuer = options.issuerUrl;

    // Technically RFC 8414 does not permit a localhost HTTPS exemption, but this will be necessary for ease of testing
    if (issuer.protocol !== "https:" && issuer.hostname !== "localhost" && issuer.hostname !== "127.0.0.1") {
        throw new Error("Issuer URL must be HTTPS");
    }
    if (issuer.hash) {
        throw new Error("Issuer URL must not have a fragment");
    }
    if (issuer.search) {
        throw new Error("Issuer URL must not have a query string");
    }

    const authorization_endpoint = "/authorize";
    const token_endpoint = "/token";
    const registration_endpoint = options.provider.clientsStore.registerClient ? "/register" : undefined;
    const revocation_endpoint = options.provider.revokeToken ? "/revoke" : undefined;
    
    const baseUrl = issuer.href.endsWith('/') ? issuer.href : `${issuer.href}/`;
    
    const metadata = {
        issuer: issuer.href,
        service_documentation: options.serviceDocumentationUrl?.href,
    
        authorization_endpoint: `${baseUrl}authorize`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
    
        token_endpoint: `${baseUrl}token`,
        token_endpoint_auth_methods_supported: ["none"],
        grant_types_supported: ["authorization_code", "refresh_token"],
    
        revocation_endpoint: revocation_endpoint ? `${baseUrl}revoke` : undefined,
        revocation_endpoint_auth_methods_supported: revocation_endpoint ? ["client_secret_post"] : undefined,
    
        registration_endpoint: registration_endpoint ? `${baseUrl}register` : undefined,
    };

    const router = express.Router();

    router.get('/callback', (req, res) => {
        const code = req.query.code;
        const encodedState = req.query.state as string;
        const error = req.query.error;
        const error_description = req.query.error_description;

        // Return 400 Bad Request if no state exists
        if (!encodedState) {
            res.status(400).json({ error: 'invalid_request', error_description: 'State parameter is required' });
            return;
        }

        let decodedState;
        let redirectUrl: URL;

        try {
            const stateJson = Buffer.from(encodedState, 'base64').toString();
            decodedState = JSON.parse(stateJson);
            redirectUrl = new URL(decodedState.originalRedirectUri);
        } catch (e) {
            // Return 400 Bad Request if cannot parse state
            res.status(400).json({ error: 'invalid_request', error_description: 'Unable to parse state parameter' });
            return;
        }

        if (error) {
            redirectUrl.searchParams.set('error', error as string);
            if (error_description) {
                redirectUrl.searchParams.set('error_description', error_description as string);
            }
        } else if (code) {
            redirectUrl.searchParams.set('code', code as string);
            if (decodedState?.state) {
                redirectUrl.searchParams.set('state', decodedState.state);
            }
        }

        res.redirect(redirectUrl.toString());
    });

    router.use(
        authorization_endpoint,
        authorizationHandler({ provider: options.provider, ...options.authorizationOptions })
    );

    router.use(
        token_endpoint,
        entraIdTokenHandler({ provider: options.provider, ...options.tokenOptions })
    );

    router.use("/.well-known/oauth-authorization-server", metadataHandler(metadata));

    if (registration_endpoint) {
        router.use(
            registration_endpoint,
            clientRegistrationHandler({
                clientsStore: options.provider.clientsStore,
                ...options,
            })
        );
    }

    if (revocation_endpoint) {
        router.use(
            revocation_endpoint,
            revocationHandler({ provider: options.provider, ...options.revocationOptions })
        );
    }

    return router;
}