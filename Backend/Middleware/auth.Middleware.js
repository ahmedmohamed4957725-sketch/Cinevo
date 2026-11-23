import { verifyToken } from "../Utils/token";
import dotenv from "dotenv";
import ApiError from "../Utils/apiError";

dotenv.config();


export default function authMiddleware(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    throw new ApiError(401, "Authorization token is missing");
  }
  try {
    const decoded = verifyToken(token);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    throw new ApiError(401, "Invalid token");
  }
}