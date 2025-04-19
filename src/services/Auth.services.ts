import config from "../config";
import { IUser } from "../interfaces/Auth.interface";
import { User } from "../models/Auth.model";
import { AppError, AuthError, NotFoundError } from "../utils/appError";
import { jwtUtils } from "../utils/jwtUtils";
import { passwordUtils } from "../utils/passwordUtils";

const registrationIntoDB = async (payload: IUser) => {
  // checking if the user is exist
  const user = await User.findOne({ phoneNumber: payload.phoneNumber });
  if (user) {
    throw new AppError("This User is Already Exists!", 409);
  }

  // Hashing Password before store user data
  const hashPassword = await passwordUtils.generateHashPassword(
    payload.password
  );

  // user data save into db
  const result = await User.create({
    ...payload,
    password: hashPassword,
  });

  return result;
};

const loginFromDB = async (payload: IUser) => {
  const { phoneNumber, password } = payload;

  // checking if the user is exist
  const user = await User.findOne({ phoneNumber });
  if (!user) {
    throw new AuthError("User not found! Please register before logging");
  }

  // checking if the password is correct
  const isCorrectPassword = await passwordUtils.comparePassword(
    password,
    user.password
  );
  if (!isCorrectPassword) {
    throw new AuthError("Incorrect password!");
  }

  // create JWT token and sent to the client
  const jwtPayload = {
    userId: user._id,
    phoneNumber: user?.phoneNumber,
    role: user.role,
  };

  // access token
  const accessToken = jwtUtils.signToken(
    jwtPayload,
    config.jwt_access_secret_key,
    { expiresIn: "1d" }
  );

  // refresh token
  const refreshToken = jwtUtils.signToken(
    jwtPayload,
    config.jwt_refresh_secret_key,
    { expiresIn: "7d" }
  );

  return {
    accessToken,
    refreshToken,
    isPhoneVerified: user.isPhoneVerified,
  };
};

const generateRefreshToken = async (token: string) => {
  // check if the token is valid
  const decoded = jwtUtils.verifyToken(token, config.jwt_refresh_secret_key);
  const { userId } = decoded;

  // checking if the user is exist
  const user = await User.findById(userId);
  if (!user) {
    throw new NotFoundError("User Not Found! Please Register.");
  }

  // JWT payload
  const jwtPayload = {
    userId: user.id,
    role: user.role,
  };

  // access token
  const accessToken = jwtUtils.signToken(
    jwtPayload,
    config.jwt_access_secret_key,
    { expiresIn: "1d" }
  );

  return { accessToken };
};

const myProfileFromDB = async (userId: string) => {
  const result = await User.findById(userId).select("-password");
  return result;
};

export const AuthServices = {
  registrationIntoDB,
  loginFromDB,
  generateRefreshToken,
  myProfileFromDB,
};
