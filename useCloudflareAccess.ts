import { Context, Next } from "hono";
import { z } from "zod";
import { seconds } from "itty-time";

export function useCloudflareAccess({
  team,
  audience,
}: {
  team: AccessTeam;
  audience: AccessAudience;
}) {
  const accessTeamDomain = AccessTeamDomain.parse(
    `https://${AccessTeam.parse(team)}.cloudflareaccess.com`
  );
  const accessAud = AccessAudience.parse(audience);

  return async (c: Context, next: Next): Promise<void> => {
    if (!hasValidJWT(c.req.raw)) {
      throw new HTTPException(401, { message: "unauthorized" });
    }

    try {
      await validateAccessJWT({
        request: c.req.raw,
        accessTeamDomain,
        accessAud,
      });
    } catch (e) {
      throw new HTTPException(401, { message: "unauthorized" });
    }

    await next();
  };
}

// Access validation code adapted from:
// https://github.com/cloudflare/pages-plugins/blob/main/packages/cloudflare-access/functions/_middleware.ts?at=90281ad52b77506bb7723a8db813e19723725509#L88

function extractJWTFromRequest(req: Request): AccessJWT {
  return AccessJWT.parse(req.headers.get("Cf-Access-Jwt-Assertion"));
}

function hasValidJWT(req: Request): boolean {
  try {
    extractJWTFromRequest(req);
    return true;
  } catch {
    return false;
  }
}

// Adapted slightly from https://github.com/cloudflare/workers-access-external-auth-example
function base64URLDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
  return new Uint8Array(
    Array.from(atob(s)).map((c: string) => c.charCodeAt(0))
  );
}

function asciiToUint8Array(s: string): Uint8Array {
  const chars = [];
  for (let i = 0; i < s.length; ++i) {
    chars.push(s.charCodeAt(i));
  }
  return new Uint8Array(chars);
}

async function validateAccessJWT({
  request,
  accessTeamDomain,
  accessAud,
}: {
  request: Request;
  accessTeamDomain: AccessTeamDomain;
  accessAud: AccessAudience;
}): Promise<{ jwt: string; payload: object }> {
  const jwt = extractJWTFromRequest(request);

  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("JWT does not have three parts.");
  }
  const [header, payload, signature] = parts;

  const textDecoder = new TextDecoder("utf-8");
  const { kid, alg } = JSON.parse(textDecoder.decode(base64URLDecode(header)));
  if (alg !== "RS256") {
    throw new Error("Unknown JWT type or algorithm.");
  }

  const certsURL = new URL("/cdn-cgi/access/certs", accessTeamDomain);
  const certsResponse = await fetch(certsURL.toString(), {
    cf: {
      cacheEverything: true,
      cacheTtl: seconds("1 day"),
    },
  });
  const { keys } = AccessCertsResponse.parse(await certsResponse.json());
  const jwk = keys.find((key) => key.kid === kid);
  if (!jwk) {
    throw new Error("Could not find matching signing key.");
  }

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const unroundedSecondsSinceEpoch = Date.now() / 1000;

  const payloadObj = AccessPayload.parse(
    JSON.parse(textDecoder.decode(base64URLDecode(payload)))
  );
  if (payloadObj.iss !== certsURL.origin) {
    throw new Error("JWT issuer is incorrect.");
  }
  if (!payloadObj.aud.includes(accessAud)) {
    throw new Error("JWT audience is incorrect.");
  }
  if (Math.floor(unroundedSecondsSinceEpoch) >= payloadObj.exp) {
    throw new Error("JWT has expired.");
  }
  // nbf is not present on service auth keys
  if (
    payloadObj.nbf &&
    Math.ceil(unroundedSecondsSinceEpoch) < payloadObj.nbf
  ) {
    throw new Error("JWT is not yet valid.");
  }

  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64URLDecode(signature),
    asciiToUint8Array(`${header}.${payload}`)
  );
  if (!verified) {
    throw new Error("Could not verify JWT.");
  }

  return { jwt, payload: payloadObj };
}

// ============= TYPES ============= //
const accessJWTRegex = /^[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+$/i;

type AccessJWT = z.infer<typeof AccessJWT>;
const AccessJWT = z.string().regex(accessJWTRegex);

type AccessTeam = z.infer<typeof AccessTeam>;
const AccessTeam = z.string().regex(/^[a-z0-9-]+$/);

type AccessTeamDomain = z.infer<typeof AccessTeamDomain>;
const AccessTeamDomain = z
  .string()
  .regex(/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/);

type AccessAudience = z.infer<typeof AccessAudience>;
const AccessAudience = z.string().regex(/^[a-f0-9]{64}$/);

type Key = z.infer<typeof Key>;
const Key = z.object({
  kid: z.string().min(1),
  kty: z.literal("RSA", { message: "unknown key type" }),
  alg: z.literal("RS256", { message: "unknown algorithm" }),
  use: z.string().min(1),
  e: z.string().min(1),
  n: z.string().min(1),
});

type PublicCERT = z.infer<typeof PublicCERT>;
const PublicCERT = z.object({
  kid: z.string(),
  cert: z.string(),
});

type AccessCertsResponse = z.infer<typeof AccessCertsResponse>;
const AccessCertsResponse = z.object({
  keys: z.array(Key).min(1, { message: "Could not fetch signing keys." }),
  public_cert: PublicCERT,
  public_certs: z.array(PublicCERT),
});

type AccessPayload = z.infer<typeof AccessPayload>;
const AccessPayload = z.object({
  aud: z.array(z.string().length(64)),
  email: z.string().min(1),
  exp: z.number(),
  iat: z.number(),
  nbf: z
    .number()
    .optional()
    .describe("nbf is not present on service auth keys"),
  iss: z.string().min(1),
  type: z.string().min(1),
  identity_nonce: z.string().min(1),
  sub: z.string().min(1),
  country: z.string().length(2),
});
