import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import express from "express";
import { createServer } from "./Tools.js";
//import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { requireBearerAuth } from "./auth/CustomBearerMiddleware.js";
import { EntraIdServerAuthProvider } from "./auth/EntraIdServerAuthProvider.js";
import getRawBody from "raw-body";
import { entraIdAuthRouter } from "./auth/EntraIdAuthRouter.js";

const app = express();

const { server, cleanup } = createServer();
const provider = new EntraIdServerAuthProvider();

let transport: SSEServerTransport;

app.get("/sse", requireBearerAuth({
  provider,
  requiredScopes: ["forerunner.mcp.act"]
}), async (req, res) => {
  console.log("Received connection");
  transport = new SSEServerTransport("/message", res);
  await server.connect(transport);

  server.onclose = async () => {
    await cleanup();
    await server.close();
    process.exit(0);
  };
});

app.post("/message", requireBearerAuth({
  provider,
  requiredScopes: ["forerunner.mcp.act"]
}), async (req, res) => {
  console.log("Received message");

  const authHeader = req.headers.authorization;
  const token = authHeader?.split(' ')[1];

  const rawBody = await getRawBody(req, {
    limit: '1mb',
    encoding: 'utf-8'
  });

  const messageBody = JSON.parse(rawBody.toString());
  if (!messageBody.params) {
    messageBody.params = {};
  }
  messageBody.params.context = { token };

  await transport.handlePostMessage(req, res, messageBody);
});

app.use(entraIdAuthRouter({
  provider: provider,
  issuerUrl: new URL('http://localhost:3001'),
  serviceDocumentationUrl: new URL('https://den.dev'),
  authorizationOptions: {},
  tokenOptions: {}
}));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
