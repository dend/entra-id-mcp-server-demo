This fork returns a virtual app registration to MCP Client, which will be converted to a shared app registration provided by MCP Server. So developers can successfully use Entra ID to authenticate between MCP Client and MCP Server without requiring Entra ID to support DCR. The MCP Server acts as a proxy to Entra ID and handles OAuth callback for the virtual app registration.

# 🔒 Minimal Entra ID-authenticated MCP Server

Minimal server showing how to implement Entra ID authentication with MCP and HTTP+SSE transport.

>[!WARNING]
>This is not intended for production use. If you are to adopt any of the practices in this implementation, ensure that you are implementing proper caching and secure token/credential handling practices.

## Run server

```
npm install
npm run build
npm run start
```

## Testing

You will need to use [**MCP Inspector**](https://github.com/modelcontextprotocol/inspector) or a tool that supports HTTP+SSE transport for MCP servers _and_ authentication.
