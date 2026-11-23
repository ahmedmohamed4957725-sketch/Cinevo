import env from "dotenv";
env.config();
//import { generateAccessToken, generateRefreshToken } from "../../Utils/token.js";
import { registerUser , loginUser , logoutUser , refreshUserTokens  } from "./auth.service.js";
import ApiResponse from "../../Utils/apiResponse.js";
import ApiError from "../../Utils/apiError.js";
import { asyncHandler } from "../../Utils/asyncHandler.js";


export const register = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    throw new ApiError(400, "name, email, and password are required");
  }
  const {user , tokens} = await registerUser({ name, email, password });

    res.cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV,
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: "/auth"
    });

    return res.status(201).json(
        new ApiResponse(
            { user, accessToken: tokens.accessToken },
            201,
            "user registered successfully"
        )
    );
});

export const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    throw new ApiError(400, "email and password are required");
  }
  const {user , tokens} = await loginUser({ email, password });

    res.cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV ,
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: "/auth"
    });

    return res.status(200).json(
        new ApiResponse(
            { user, accessToken: tokens.accessToken },
            200,
            "user logged in successfully"
        )
    );
});

export const logout = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies?.refreshToken;

    await logoutUser(refreshToken);

    res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/auth"
    });

    return res.status(200).json(
        new ApiResponse(
            null,
            200,
            "Logged out successfully"
        )
    );
});


export const refresh = asyncHandler(async (req, res) => {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
        throw new ApiError(401, "Refresh token is required");
    }

    const { user, tokens } = await refreshUserTokens(refreshToken);

    res.cookie("refreshToken", tokens.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: "/auth"
    });

    return res.status(200).json(
        new ApiResponse(
            {
                user,
                accessToken: tokens.accessToken
            },
            200,
            "Token refreshed successfully"
        )
    );
});



