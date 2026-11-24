// Test fixture for js-endpoint-auth.yml — run: semgrep --test security/endpoint-auth/rules
// `ruleid:` marks a line that MUST match, `ok:` marks a line that must NOT match.
import * as functions from "firebase-functions";
import { onRequest } from "firebase-functions/v2/https";

// ---------------------------------------------------------------- access-jwt-presence-only
function isAuthorizedPresence(request: Request, env: any): boolean {
  // ruleid: access-jwt-presence-only
  const cfAccess = request.headers.get("cf-access-jwt-assertion");
  if (cfAccess) {
    return true; // trusted because the header exists
  }
  return false;
}

function isAuthorizedPresenceInline(request: Request): boolean {
  // ruleid: access-jwt-presence-only
  if (request.headers.get("Cf-Access-Jwt-Assertion")) {
    return true;
  }
  return false;
}

async function isAuthorizedVerified(request: Request, env: any): Promise<boolean> {
  const token = request.headers.get("cf-access-jwt-assertion");
  // ok: access-jwt-presence-only
  if (!token) {
    return false;
  }
  await verify(token, env);
  return true;
}

// ---------------------------------------------------------------- access-identity-header-trusted
function actorFromHeader(request: Request): string | null {
  // ruleid: access-identity-header-trusted
  return request.headers.get("Cf-Access-Authenticated-User-Email");
}

const ACCESS_HEADER = "cf-access-authenticated-user-email";
function actorFromConstHeader(request: Request): string | null {
  // ruleid: access-identity-header-trusted
  return request.headers.get(ACCESS_HEADER);
}

function actorFromHonoHeader(c: any): string | undefined {
  // ruleid: access-identity-header-trusted
  return c.req.header("Cf-Access-Authenticated-User-Email")?.trim();
}

function contentType(request: Request): string | null {
  // ok: access-identity-header-trusted
  return request.headers.get("content-type");
}

// ---------------------------------------------------------------- auth-fails-open-when-secret-unset
function checkKey(request: Request, env: any): boolean {
  const apiKey = request.headers.get("x-api-key");
  if (apiKey && env.ADMIN_API_KEY && apiKey === env.ADMIN_API_KEY) {
    return true;
  }
  // ruleid: auth-fails-open-when-secret-unset
  if (!env.ADMIN_API_KEY) {
    return true;
  }
  return false;
}

async function handle(request: Request, env: any): Promise<Response> {
  const apiKey = request.headers.get("x-api-key");
  // ruleid: auth-fails-open-when-secret-unset
  if (env.SERVICE_API_KEY && apiKey !== env.SERVICE_API_KEY) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  return new Response("ok");
}

const KEY = process.env.SERVICE_KEY || "";
function nodeHandler(req: any, res: any) {
  // ruleid: auth-fails-open-when-secret-unset
  if (KEY && req.headers["x-service-key"] !== KEY) {
    res.writeHead(401);
    return res.end("unauthorized");
  }
}

function failClosed(request: Request, env: any): boolean {
  // ok: auth-fails-open-when-secret-unset
  if (!env.ADMIN_API_KEY) {
    return false;
  }
  return request.headers.get("x-api-key") === env.ADMIN_API_KEY;
}

function unrelatedFlag(env: any): boolean {
  // ok: auth-fails-open-when-secret-unset
  if (!env.FEATURE_ENABLED) {
    return true;
  }
  return false;
}

// ---------------------------------------------------------------- hardcoded-secret-fallback
export const isAuthed = (req: any) => {
  // ruleid: hardcoded-secret-fallback
  const SECRET = process.env.WORKER_SHARED_KEY || "a1B2c3D4e5F6g7H8i9J0";
  return req.get("x-api-key") === SECRET;
};

// ok: hardcoded-secret-fallback
const REGION = process.env.REGION || "us-central1-default";
// ok: hardcoded-secret-fallback
const EMPTY = process.env.SOME_API_KEY || "";

// ---------------------------------------------------------------- bearer-compare-against-unset-secret
function bearerCheck(request: Request, env: any): boolean {
  const auth = request.headers.get("Authorization");
  // ruleid: bearer-compare-against-unset-secret
  return auth === `Bearer ${env.WEBHOOK_TOKEN}`;
}

// ---------------------------------------------------------------- http-cloud-function-without-auth
// ruleid: http-cloud-function-without-auth
export const createRecord = functions.runWith({ memory: "512MB" }).https.onRequest(async (req, res) => {
  const clientId = req.body.clientId;
  await db.collection("things").add({ clientId, ...req.body });
  res.status(200).send("ok");
});

// ok: http-cloud-function-without-auth
export const createRecordAuthed = functions.https.onRequest(async (req, res) => {
  if (req.headers["x-api-key"] !== process.env.THING_API_KEY) {
    res.status(401).send("unauthorized");
    return;
  }
  res.status(200).send("ok");
});

// ok: http-cloud-function-without-auth
export const createRecordHelper = functions.https.onRequest(async (req, res) => {
  if (!isAuthed(req)) {
    res.status(401).send("unauthorized");
    return;
  }
  res.status(200).send("ok");
});

// ruleid: http-cloud-function-without-auth
export const v2Thing = onRequest({ cors: true }, async (req, res) => {
  res.json(await db.collection("clients").get());
});

function requestKeyOptional(req: any, next: any) {
  const reqApiKey = req.headers["x-api-key"];
  // ok: auth-fails-open-when-secret-unset
  if (!reqApiKey) {
    return next();
  }
}

function objectKeyCheck(objectKey: string): boolean {
  // ok: auth-fails-open-when-secret-unset
  if (!validObjectKey(objectKey)) {
    return true;
  }
  return false;
}

// ok: hardcoded-secret-fallback
const TOKEN_FILE = process.env.CLIENT_TOKEN_FILE ?? "./.client-auth-store.json";
// ok: hardcoded-secret-fallback
const SECRET_NAME = process.env.SERVICE_API_KEY || "service-api-key-name";

declare function validObjectKey(k: string): boolean;
declare const db: any;
declare function verify(t: string, e: any): Promise<void>;

export const lettersOnlyKey = () => {
  // ruleid: hardcoded-secret-fallback
  const SECRET = process.env.WORKER_API_KEY || "qWeRtYuIoPaSdFgHjKlZx";
  return SECRET;
};
