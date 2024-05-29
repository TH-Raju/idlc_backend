import express from "express";
import { userController } from "./user.controller.js";
import { auth } from "../../middlewares/auth.js";
import { USER_ROLE } from "../../helpers/userRole.js";
import fileUpload from "../../middlewares/fileUpload.js";

const upload = fileUpload("./src/uploads/profile/");
const userRouter = express.Router();

userRouter
  .get(
    "/",
    auth.verifyRole(USER_ROLE.ADMIN, USER_ROLE.SUPER_ADMIN),
    userController.getAllUsers
  )
  .get("/:id", userController.getSingleUser)
  .put("/:id", upload.single("photo"), userController.updateUser)
  .post("/forget-password", userController.forgetPassword)
  .delete(
    "/:id",
    auth.verifyRole(USER_ROLE.ADMIN, USER_ROLE.SUPER_ADMIN),
    userController.deleteUser
  )
  .patch("/reset-password", userController.resetPassword)
  .patch("/otp/forget-password", userController.verifyForgetOtp)
  .post("/signup", userController.addUser)
  .post("/verify-otp", userController.verifyUser)
  .post("/login", userController.login);

export default userRouter;
