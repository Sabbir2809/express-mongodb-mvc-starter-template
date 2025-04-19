import { Request, Response } from "express";
import { JwtPayload } from "jsonwebtoken";
import config from "../config";
import { AuthServices } from "../services/Auth.services";
import catchAsync from "../utils/catchAsync";
import sendResponse from "../utils/sendResponse";

const registration = catchAsync(async (req: Request, res: Response) => {
  // service
  const result = await AuthServices.registrationIntoDB(req.body);

  // send response
  sendResponse(res, {
    success: true,
    statusCode: 201,
    message: "User registered successfully",
    data: result,
  });
});

const login = catchAsync(async (req: Request, res: Response) => {
  // service
  const result = await AuthServices.loginFromDB(req.body);
  const { refreshToken, accessToken } = result;

  // cookie
  res.cookie("refreshToken", refreshToken, {
    secure: config.node_environment === "production",
    httpOnly: true,
  });

  // send response
  sendResponse(res, {
    success: true,
    statusCode: 200,
    message: "User Login Successfully",
    data: { accessToken, refreshToken },
  });
});

const refreshToken = catchAsync(async (req: Request, res: Response) => {
  const { refreshToken } = req.cookies;
  // service
  const { accessToken } = await AuthServices.generateRefreshToken(refreshToken);

  // send response
  sendResponse(res, {
    success: true,
    statusCode: 201,
    message: "Access Token Retrieved Successfully",
    data: accessToken,
  });
});

const myProfile = catchAsync(async (req: Request, res: Response) => {
  const { userId } = req.user as JwtPayload;
  // service
  const result = await AuthServices.myProfileFromDB(userId);

  // send response
  sendResponse(res, {
    success: true,
    statusCode: 200,
    message: "My Profile Retrieved Successfully",
    data: result,
  });
});

export const AuthControllers = {
  registration,
  login,
  refreshToken,
  myProfile,
};
