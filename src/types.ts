import type {
  AuthAccountFacade,
  AuthAdminFacade,
  AuthPublicFacade,
  Session,
  User,
} from "@alyldas/uniauth-core";
import type {
  CookieOptions,
  ErrorRequestHandler,
  RequestHandler,
  Router,
} from "express";

export interface UniAuthExpressService {
  readonly public: AuthPublicFacade;
  readonly account: AuthAccountFacade;
  readonly admin: AuthAdminFacade;
}

export interface UniAuthRequestAuth {
  readonly sessionToken: string;
  readonly session: Session;
  readonly user: User;
  readonly userId: Session["userId"];
}

export interface UniAuthSessionCookieOptions {
  readonly name?: string;
  readonly encode?: (sessionToken: string) => string | Promise<string>;
  readonly decode?: (
    value: string,
  ) => string | undefined | Promise<string | undefined>;
  readonly options?: CookieOptions;
}

export interface UniAuthSessionTransportOptions {
  readonly cookie?: UniAuthSessionCookieOptions | false;
  readonly bearer?: boolean;
  readonly touch?: boolean;
}

export interface UniAuthExpressOptions {
  readonly auth: UniAuthExpressService;
  readonly session?: UniAuthSessionTransportOptions;
  readonly csrf?: RequestHandler;
  readonly adminGuard?: RequestHandler;
}

export interface UniAuthRouterSet {
  readonly public: Router;
  readonly account: Router;
  readonly admin: Router;
}

export interface UniAuthErrorMappingOptions {
  readonly exposeInternalErrors?: boolean;
}

export type UniAuthErrorHandler = ErrorRequestHandler;
