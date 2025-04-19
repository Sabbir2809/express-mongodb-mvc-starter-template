import { Router } from "express";
import { AuthRoutes } from "./Auth.routes";

const globalRouter = Router();

const moduleRoutes = [
  {
    path: "/auth",
    route: AuthRoutes,
  },
];

moduleRoutes.forEach((route) => globalRouter.use(route.path, route.route));

export default globalRouter;
