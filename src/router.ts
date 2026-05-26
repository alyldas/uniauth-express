import { Router } from "express";
import { createUniAuthErrorHandler } from "./errors.js";
import { createUniAuthSessionMiddleware } from "./middleware.js";
import { createUniAuthAccountRouter } from "./routes/account.js";
import { createUniAuthAdminRouter } from "./routes/admin.js";
import { createUniAuthPublicRouter } from "./routes/public.js";
import type { UniAuthExpressOptions, UniAuthRouterSet } from "./types.js";

export function createUniAuthRouters(
  options: UniAuthExpressOptions,
): UniAuthRouterSet {
  return {
    public: createUniAuthPublicRouter(options),
    account: Router().use(
      createUniAuthSessionMiddleware(options.auth, options.session),
      createUniAuthAccountRouter(options),
    ),
    admin: createUniAuthAdminRouter(options),
  };
}

export function createUniAuthExpressRouter(
  options: UniAuthExpressOptions,
): Router {
  const router = Router();
  const routers = createUniAuthRouters(options);

  router.use(routers.public);
  router.use("/account", routers.account);
  router.use("/admin", routers.admin);
  router.use(createUniAuthErrorHandler());

  return router;
}
