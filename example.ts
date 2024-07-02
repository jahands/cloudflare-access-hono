import { Hono } from "hono"

const app = new Hono()

  // Routes protected by Cloudflare Access
  .use(
    "/logs*",
    useCloudflareAccess({
      team: "myteam",
      audience:
        // Gotten from Cloudflare ZT Dashboard for app
        "a1b1c1d1e1f1g1a1b1c1d1e1f1g1a1b1c1d1e1f1g1a1b1c1d1e1f1g1a1b1c1d1",
    })
  );

export default app
