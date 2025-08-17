/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextFunction, Request, Response } from "express";
import config from "../config";
import { User } from "../models/Auth.model";
import { AuthError, ForbiddenError } from "../utils/appError";
import catchAsync from "../utils/catchAsync";
import { jwtUtils } from "../utils/jwtUtils";

const authGuard = (...requiredRoles: string[]) => {
  return catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    // headers token
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(" ")[1];

    if (!token) {
      throw new AuthError("Authorization token is required! Please Login.");
    }

    // check if the token is valid
    let decodedToken;
    try {
      decodedToken = jwtUtils.verifyToken(token, config.jwt_access_secret_key);
    } catch (error) {
      throw new AuthError();
    }

    // decoded token
    const { userId, role, iat } = decodedToken;

    // Expired date
    if (!iat) {
      throw new AuthError(
        "Session Expired or Invalid. Please Login Again To Continue."
      );
    }

    // Authentication
    const user = await User.findById(userId);
    if (!user) {
      throw new AuthError("User Not Found! Please register before logging");
    }

    // authorization
    if (requiredRoles && !requiredRoles.includes(role)) {
      throw new ForbiddenError();
    }

    // decoded
    req.user = decodedToken;
    next();
  });
};

export default authGuard;
