import jwt from "jsonwebtoken";
import catchAsync from "../shared/catchAsync.js";
import sendResponse from "../shared/sendResponse.js";
import config from "../config/index.js";

const isValidUser = catchAsync(async (req, res, next) => {
  const { authorization } = req.headers;
  let token;
  let decodedData;
  if (authorization && authorization.startsWith("Bearer")) {
    token = authorization.split(" ")[1];
    if (token && token !== undefined && token !== null && token !== "null") {
      decodedData = jwt.verify(token, config.access_secret);
    }
  }
  if (!authorization || !decodedData) {
    return sendResponse(res, 401, false, "Unauthorized", {});
  }
  req.body.userId = decodedData._id;
  req.body.userRole = decodedData.role;
  req.body.userEmail = decodedData.email;
  req.body.userFullName = decodedData.fullName;
  next();
});

const tokenCheck = catchAsync(async (req, res, next) => {
  const { signuptoken } = req.headers;
  if (signuptoken && signuptoken.startsWith("signUpToken")) {
    const token = signuptoken.split(" ")[1];
    const decodedData = jwt.verify(token, config.refresh_secret);
    req.body.userData = decodedData;
  }
  next();
});

const noCheck = async (req, res, next) => {
  try {
    const { authorization } = req.headers;
    let token;
    let decodedData;
    if (authorization && authorization.startsWith("Bearer")) {
      token = authorization.split(" ")[1];
      decodedData = jwt.verify(token, config.jwt_access_token);
    } else {
      return next();
    }
    req.body.userId = decodedData._id;
    next();
  } catch (err) {
    console.log(err);
    next();
  }
};

const verifyRole = (...roles) => {
  return async (req, res, next) => {
    try {
      const token = req.headers.authorization;
      console.log("---------------------------->", token);
      // req.headers.authorization && req.headers.authorization.split(" ")[1];
      if (!token) {
        return sendResponse(res, 401, false, "Invalid authorization", {});
      }
      const verifiedUser = jwt.verify(token, config.access_secret);

      req.user = verifiedUser;

      if (roles.length && !roles.includes(verifiedUser.role)) {
        return sendResponse(res, 403, false, "Roles doesn't match", {});
      }

      next();
    } catch (error) {
      console.log(error);
      next(error);
    }
  };
};

export const auth = { isValidUser, tokenCheck, noCheck, verifyRole };
