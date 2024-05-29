import express from "express";
import userRouter from "../modules/User/user.route.js";

const rootRouter = express.Router();

const moduleRoutes = [{ path: "/users", router: userRouter }];

moduleRoutes.forEach((route) => {
  rootRouter.use(route.path, route.router);
});

export default rootRouter;
