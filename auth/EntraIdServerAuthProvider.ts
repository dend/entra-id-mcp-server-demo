import { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { OAuthClientInformationFull, OAuthTokens, OAuthTokenRevocationRequest } from "@modelcontextprotocol/sdk/shared/auth.js";
import { Response } from "express";
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { PublicClientApplication } from "@azure/msal-node";
import { ClientWithVerifier } from "./ClientWithVerifier.js";
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';

/**
 * Configuration for Entra ID authentication
 */
interface EntraIdConfig {
    tenantId: string;
    clientId: string;
    apiClientId: string;
    scopes: string[];
}

export class EntraIdServerAuthProvider implements OAuthServerProvider {
    private _clientsMap: Map<string, OAuthClientInformationFull> = new Map();
    private _clientsStoreImpl: OAuthRegisteredClientsStore;
    private _config: EntraIdConfig;
    private _clientsFilePath: string;
    private _msalClient: PublicClientApplication;

    /**
     * Creates a new instance of EntraIdServerAuthProvider
     */
    constructor() {
        dotenv.config();

        const requiredEnvVars = ['FR_TENANT_ID', 'FR_PUBLIC_CLIENT_ID', 'FR_API_CLIENT_ID'];
        
        const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
        if (missingEnvVars.length > 0) {
            throw new Error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
        }

        this._config = {
            tenantId: process.env.FR_TENANT_ID!,
            clientId: process.env.FR_PUBLIC_CLIENT_ID!,
            apiClientId: process.env.FR_API_CLIENT_ID!,
            scopes: [`api://${process.env.FR_API_CLIENT_ID}/forerunner.mcp.act`]
        };

        this._msalClient = this.createMsalClient();

        this._clientsFilePath = path.resolve(process.cwd(), 'registered_clients.json');

        this._clientsStoreImpl = {
            getClient: (clientId: string) => {
                console.log("Getting client ", clientId);
                return this._clientsMap.get(clientId);
            },

            registerClient: (client: OAuthClientInformationFull) => {
                this._clientsMap.set(client.client_id, client);
                console.log("Registered client ", client.client_id);
                // Save updated clients list to file
                this._saveClientsToFile().catch(err => {
                    console.error("Failed to save client registration:", err);
                });
                return client;
            }
        };

        // Load existing clients on startup
        this._loadClientsFromFile().catch(err => {
            console.error("Failed to load registered clients:", err);
        });
    }

    /**
     * Load registered clients from file
     */
    private async _loadClientsFromFile(): Promise<void> {
        try {
            await fs.access(this._clientsFilePath)
                .catch(() => {
                    console.log("No saved clients file found. Starting with empty clients list.");
                    return Promise.reject(new Error("File not found"));
                });

            const fileContent = await fs.readFile(this._clientsFilePath, { encoding: 'utf8' });
            const clientsData = JSON.parse(fileContent);

            this._clientsMap.clear();
            for (const [clientId, clientData] of Object.entries(clientsData)) {
                this._clientsMap.set(clientId, clientData as OAuthClientInformationFull);
            }

            console.log(`Loaded ${this._clientsMap.size} registered clients from file.`);
        } catch (err) {
            if ((err as Error).message !== "File not found") {
                console.error("Error loading clients from file:", err);
            }
        }
    }

    /**
     * Save registered clients to file
     */
    private async _saveClientsToFile(): Promise<void> {
        try {
            const clientsObject: Record<string, OAuthClientInformationFull> = {};
            for (const [clientId, clientData] of this._clientsMap.entries()) {
                clientsObject[clientId] = clientData;
            }

            await fs.writeFile(
                this._clientsFilePath,
                JSON.stringify(clientsObject, null, 2),
                { encoding: 'utf8' }
            );

            console.log(`Saved ${this._clientsMap.size} registered clients to file.`);
        } catch (err) {
            console.error("Error saving clients to file:", err);
            throw err;
        }
    }

    /**
     * Gets the clients store implementation
     */
    get clientsStore(): OAuthRegisteredClientsStore {
        return this._clientsStoreImpl;
    }

    /**
     * Creates a configured MSAL client application
     * @param redirectUri - The redirect URI to use
     * @returns Configured PublicClientApplication
     */
    private createMsalClient(redirectUri?: string): PublicClientApplication {
        return new PublicClientApplication({
            auth: {
                clientId: this._config.clientId,
                authority: `https://login.microsoftonline.com/${this._config.tenantId}`,
                ...(redirectUri && { redirectUri })
            }
        });
    }

    /**
     * Authorizes a client and redirects to Entra ID login
     * @param client - Client information
     * @param params - Authorization parameters
     * @param res - Express response object
     */
    async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
        console.log("Authorizing client ", client.client_id);

        try {
            const originalRedirectUri = client.redirect_uris[0] as string;
            const redirectUri = 'http://localhost:3001/callback';
            const codeChallenge = params.codeChallenge as string;
            const codeChallengeMethod = 'S256';
            const state = Buffer.from(JSON.stringify({
                originalRedirectUri,
                state: params.state
            })).toString('base64');

            if (!this._config.clientId) {
                res.status(400).send("Missing client ID configuration");
                return;
            }

            this._msalClient.getAuthCodeUrl({
                scopes: this._config.scopes,
                redirectUri: redirectUri,
                responseMode: "query",
                codeChallenge: codeChallenge,
                codeChallengeMethod: codeChallengeMethod,
                state: state
            })
                .then(authUrl => {
                    res.redirect(authUrl);
                })
                .catch(error => {
                    console.error("Error generating auth URL:", error);
                    res.status(500).send("Authentication error occurred");
                });
        } catch (error) {
            console.error("Authorization setup error:", error);
            res.status(500).send("Failed to initialize authentication");
        }
    }

    /**
     * This function is a NOOP. This is already handled by Entra ID.
     * @param client - Client information
     * @param authorizationCode - The authorization code
     * @returns Promise with the code challenge
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
        return Promise.resolve('');
    }

    /**
     * Exchanges an authorization code for a bearer access token. The server in this
     * context does not cache the tokens in any capacity, but rather gives that responsibility
     * to the client, who will request a new token when needed.
     * @param client - Client with verifier
     * @param authorizationCode - The authorization code
     * @returns Promise with OAuth tokens
     */
    async exchangeAuthorizationCode(client: ClientWithVerifier, authorizationCode: string): Promise<OAuthTokens> {
        try {
            const redirectUri = client.redirect_uris[0] as string;
            const redirectUrl = new URL(redirectUri);
            if (redirectUrl.hostname !== 'localhost' && redirectUrl.hostname !== '127.0.0.1') {
                throw new Error(`Invalid redirect URI: ${redirectUri}. Only localhost redirects are allowed.`);
            }

            const tokenResponse = await this._msalClient.acquireTokenByCode({
                code: authorizationCode,
                scopes: this._config.scopes,
                redirectUri: 'http://localhost:3001/callback',
                codeVerifier: client.verifier,
            });

            if (!tokenResponse) {
                throw new Error("Failed to acquire token");
            }

            // Return the tokens in the format expected by OAuthTokens
            return {
                access_token: tokenResponse.accessToken,
                token_type: 'Bearer',
                expires_in: tokenResponse.expiresOn ?
                    Math.floor((tokenResponse.expiresOn.getTime() - Date.now()) / 1000) :
                    3600, // Default to 1 hour if expiration is not provided
                scope: tokenResponse.scopes.join(' ')
            };
        } catch (error) {
            console.error("Error exchanging authorization code for tokens:", error);
            throw new Error(`Failed to exchange authorization code: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Exchanges a refresh token for new OAuth tokens
     * @param client - Client information
     * @param refreshToken - The refresh token
     * @param scopes - Optional scopes to request
     * @returns Promise with OAuth tokens
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string, scopes?: string[]): Promise<OAuthTokens> {
        // TODO: Implement refresh token functionality
        throw new Error("Refresh token exchange not implemented");
    }

    /**
     * Verifies an access token and returns authentication information.
     * This method is invoked in the context of bearerAuth infra inside
     * the auth middleware. It get an AuthInfo object and then checks if
     * all required sceopes are included or the token has expired. It assumes
     * that the bulk of validation (beyond that) happens here.
     * @param token - The access token to verify
     * @returns Promise with authentication information
     */
    async verifyAccessToken(token: string): Promise<AuthInfo> {
        try {
            const decodedToken = jwt.decode(token, { complete: true });
            if (!decodedToken || typeof decodedToken === 'string' || !decodedToken.header.kid) {
                throw new Error('Invalid token format');
            }

            const payload = decodedToken.payload as jwt.JwtPayload;

            const openIdConfigUrl = `https://login.microsoftonline.com/${this._config.tenantId}/v2.0/.well-known/openid-configuration`;

            const openIdConfigResponse = await fetch(openIdConfigUrl);
            const openIdConfigData = await openIdConfigResponse.json();
            const jwksUri = openIdConfigData.jwks_uri;

            const keyClient = jwksClient({
                jwksUri: jwksUri,
                cache: true,
                cacheMaxEntries: 5,
                cacheMaxAge: 600000 // 10 minutes
            });

            const getSigningKey = (kid: string): Promise<jwksClient.SigningKey> => {
                return new Promise((resolve, reject) => {
                    keyClient.getSigningKey(kid, (err, key) => {
                        if (err) {
                            reject(err);
                            return;
                        }
                        if (!key) {
                            reject(new Error('Signing key not found'));
                            return;
                        }
                        resolve(key);
                    });
                });
            };

            const key = await getSigningKey(decodedToken.header.kid);
            const signingKey = key.getPublicKey();

            jwt.verify(token, signingKey, {
                audience: this._config.apiClientId,
                issuer: `https://login.microsoftonline.com/${this._config.tenantId}/v2.0`
            });

            return {
                clientId: Array.isArray(payload.aud) ? payload.aud[0] : payload.aud || '',
                token: token,
                expiresAt: payload.exp || 0,
                scopes: (payload.scp || '').split(' ').filter(Boolean),
            };
        } catch (error) {
            console.error('Token processing failed:', error);
            
            // Given that inside the middleware the failure occurs if expiration is less than
            // now, we can return an object with whatever is in the token and set the expiration
            // to 0. This will cause the middleware to fail the check and return a 401, which
            // should restart the authentication flow.
            return {
                clientId: '',
                token: token,
                expiresAt: 0,
                scopes: ["forerunner.mcp.act"],
            };
        }
    }

    /**
     * Revokes an OAuth token
     * @param client - Client information
     * @param request - Token revocation request
     * @returns Promise indicating completion
     */
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
        // TODO: Implement token revocation functionality
        throw new Error("Token revocation not implemented");
    }
}