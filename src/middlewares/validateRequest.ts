import { NextFunction, Request, Response } from "express";
import { ZodObject, ZodRawShape, ZodTypeAny } from "zod";
import catchAsync from "../utils/catchAsync";

const validateRequest = (schema: ZodObject<ZodRawShape> | ZodTypeAny) => {
  return catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    await schema.parseAsync({
      body: req.body,
      cookies: req.cookies,
      query: req.query,
      params: req.params,
    });
    next();
  });
};

export default validateRequest;
