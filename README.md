# 🔒 Minimal Entra ID-authenticated MCP Server

Minimal server showing how to implement Entra ID authentication with MCP and HTTP+SSE transport.

>[!IMPORTANT]
>This repository has been archived. Refer to the [reference collection](https://github.com/localden/mcp-auth-servers) for latest samples and best practices.

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
