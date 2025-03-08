import { z } from "zod";
import express, { RequestHandler } from "express";
import { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import cors from "cors";
import { authenticateClient } from "@modelcontextprotocol/sdk/server/auth/middleware/clientAuth.js";
import { rateLimit, Options as RateLimitOptions } from "express-rate-limit";
import { allowedMethods } from "@modelcontextprotocol/sdk/server/auth/middleware/allowedMethods.js";
import {
    InvalidRequestError,
    UnsupportedGrantTypeError,
    ServerError,
    TooManyRequestsError,
    OAuthError
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { ClientWithVerifier } from "./ClientWithVerifier.js";

export type TokenHandlerOptions = {
    provider: OAuthServerProvider;
    /**
     * Rate limiting configuration for the token endpoint.
     * Set to false to disable rate limiting for this endpoint.
     */
    rateLimit?: Partial<RateLimitOptions> | false;
};

const TokenRequestSchema = z.object({
    grant_type: z.string(),
});

const AuthorizationCodeGrantSchema = z.object({
    code: z.string(),
    code_verifier: z.string(),
});

const RefreshTokenGrantSchema = z.object({
    refresh_token: z.string(),
    scope: z.string().optional(),
});

export function entraIdTokenHandler({ provider, rateLimit: rateLimitConfig }: TokenHandlerOptions): RequestHandler {
    // Nested router so we can configure middleware and restrict HTTP method
    const router = express.Router();

    // Configure CORS to allow any origin, to make accessible to web-based MCP clients
    router.use(cors());

    router.use(allowedMethods(["POST"]));
    router.use(express.urlencoded({ extended: false }));

    // Apply rate limiting unless explicitly disabled
    if (rateLimitConfig !== false) {
        router.use(rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 50, // 50 requests per windowMs 
            standardHeaders: true,
            legacyHeaders: false,
            message: new TooManyRequestsError('You have exceeded the rate limit for token requests').toResponseObject(),
            ...rateLimitConfig
        }));
    }

    // Authenticate and extract client details
    router.use(authenticateClient({ clientsStore: provider.clientsStore }));

    router.post("/", async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');

        try {
            const parseResult = TokenRequestSchema.safeParse(req.body);
            if (!parseResult.success) {
                throw new InvalidRequestError(parseResult.error.message);
            }

            const { grant_type } = parseResult.data;

            const client = req.client;
            if (!client) {
                // This should never happen
                console.error("Missing client information after authentication");
                throw new ServerError("Internal Server Error");
            }

            switch (grant_type) {
                case "authorization_code": {
                    const parseResult = AuthorizationCodeGrantSchema.safeParse(req.body);
                    if (!parseResult.success) {
                        throw new InvalidRequestError(parseResult.error.message);
                    }

                    const { code, code_verifier } = parseResult.data;

                    const clientWithVerifier: ClientWithVerifier = {
                        ...client,
                        verifier: code_verifier
                    };

                    const tokens = await provider.exchangeAuthorizationCode(clientWithVerifier, code);
                    res.status(200).json(tokens);
                    break;
                }

                case "refresh_token": {
                    const parseResult = RefreshTokenGrantSchema.safeParse(req.body);
                    if (!parseResult.success) {
                        throw new InvalidRequestError(parseResult.error.message);
                    }

                    const { refresh_token, scope } = parseResult.data;

                    const scopes = scope?.split(" ");
                    const tokens = await provider.exchangeRefreshToken(client, refresh_token, scopes);
                    res.status(200).json(tokens);
                    break;
                }

                default:
                    throw new UnsupportedGrantTypeError(
                        "The grant type is not supported by this authorization server."
                    );
            }
        } catch (error) {
            if (error instanceof OAuthError) {
                const status = error instanceof ServerError ? 500 : 400;
                res.status(status).json(error.toResponseObject());
            } else {
                console.error("Unexpected error exchanging token:", error);
                const serverError = new ServerError("Internal Server Error");
                res.status(500).json(serverError.toResponseObject());
            }
        }
    });

    return router;
}