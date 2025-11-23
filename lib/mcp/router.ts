import { db } from "@/lib/db/client";
import type { ApiKey, Merchant, User } from "@prisma/client";
import { z, type ZodSchema } from "zod";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface McpAuthContext {
  apiKey: ApiKey;
  user: User & { merchant?: Merchant | null };
  merchant: Merchant | null;
}

export interface McpHandlerContext<TBody = unknown> {
  request: Request;
  method: HttpMethod;
  query: URLSearchParams;
  params?: Record<string, string>;
  body: TBody;
  auth?: McpAuthContext;
}

export type McpHandler<TBody = unknown> = (
  context: McpHandlerContext<TBody>
) => Promise<Response>;

interface RouteOptions<TBody> {
  requireAuth?: boolean;
  schema?: ZodSchema<TBody>;
}

interface RegisteredRoute {
  handler: McpHandler;
  requireAuth: boolean;
  schema?: ZodSchema<any>;
}

export interface RouterOptions {
  requireAuthByDefault?: boolean;
}

export class McpRouter {
  private routes = new Map<HttpMethod, RegisteredRoute>();
  private requireAuthByDefault: boolean;

  constructor(options: RouterOptions = {}) {
    this.requireAuthByDefault = options.requireAuthByDefault ?? true;
  }

  register<TBody = unknown>(
    method: HttpMethod,
    handler: McpHandler<TBody>,
    options: RouteOptions<TBody> = {}
  ) {
    this.routes.set(method, {
      handler: handler as McpHandler,
      requireAuth: options.requireAuth ?? this.requireAuthByDefault,
      schema: options.schema,
    });
  }

  async handle(
    request: Request,
    context?: { params?: Record<string, string> }
  ): Promise<Response> {
    const method = request.method.toUpperCase() as HttpMethod;
    const route = this.routes.get(method);

    if (!route) {
      return jsonError("Method Not Allowed", 405);
    }

    const contentType = request.headers.get("content-type") || "";
    let body: unknown = undefined;

    if (contentType.includes("application/json")) {
      try {
        body = await request.json();
      } catch (error) {
        return jsonError("Invalid JSON body", 400, {
          detail:
            error instanceof Error ? error.message : "Unable to parse request body",
        });
      }
    }

    if (route.schema) {
      const parsed = route.schema.safeParse(body);
      if (!parsed.success) {
        return jsonError("Validation failed", 400, {
          issues: parsed.error.issues,
        });
      }
      body = parsed.data;
    }

    let auth: McpAuthContext | undefined;

    if (route.requireAuth) {
      auth = await authenticateRequest(request);
      if (!auth) {
        return jsonError("Unauthorized", 401, {
          detail: "Missing or invalid MCP API key",
        });
      }
    }

    const handlerContext: McpHandlerContext = {
      request,
      method,
      query: new URL(request.url).searchParams,
      params: context?.params,
      body,
      auth,
    };

    try {
      return await route.handler(handlerContext);
    } catch (error) {
      console.error("[MCP Router] Handler error:", error);
      return jsonError("Internal Server Error", 500, {
        detail: error instanceof Error ? error.message : "Unknown error",
      });
    }
  }
}

export function createMcpRouter(options?: RouterOptions) {
  return new McpRouter(options);
}

async function authenticateRequest(
  request: Request
): Promise<McpAuthContext | undefined> {
  const apiKeyHeader =
    request.headers.get("x-mcp-key") ||
    request.headers.get("x-api-key") ||
    extractBearerToken(request.headers.get("authorization"));

  if (!apiKeyHeader) {
    return undefined;
  }

  const apiKey = await db.apiKey.findUnique({
    where: { key: apiKeyHeader },
    include: {
      user: {
        include: {
          merchant: true,
        },
      },
    },
  });

  if (!apiKey || !apiKey.user) {
    return undefined;
  }

  return {
    apiKey,
    user: apiKey.user,
    merchant: apiKey.user.merchant ?? null,
  };
}

function extractBearerToken(header: string | null): string | null {
  if (!header) return null;
  const [scheme, token] = header.split(" ");
  if (!scheme || scheme.toLowerCase() !== "bearer" || !token) {
    return null;
  }
  return token.trim();
}

export function jsonResponse<T>(data: T, init?: ResponseInit) {
  return new Response(JSON.stringify(data), {
    status: init?.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...(init?.headers || {}),
    },
  });
}

export function jsonError(
  message: string,
  status: number,
  meta?: Record<string, unknown>
) {
  return jsonResponse(
    {
      error: message,
      ...(meta || {}),
    },
    { status }
  );
}

export const paginationSchema = z.object({
  limit: z.coerce.number().min(1).max(100).default(20),
  cursor: z.string().optional(),
});

