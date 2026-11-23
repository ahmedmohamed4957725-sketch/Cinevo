import db from "../../Config/db.js";
import ApiError from "../../Utils/apiError.js";
import { hashPassword, comparePassword } from "../../Utils/password.js";
import {
    generateAccessToken,
    generateRefreshToken,
    hashToken,
    verifyRefreshToken
} from "../../Utils/token.js";

const toPublicUser = (user) => ({
    id: user.id,
    name: user.name,
    email: user.email,
    created_at: user.created_at,
});
const createUserTokens = async (user) => {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const tokenHash = hashToken(refreshToken);
    

    await db.query(
        `INSERT INTO refresh_tokens
         (user_id, token_hash, expires_at)
         VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
        [user.id, tokenHash]
    );

    return {
        accessToken,
        refreshToken
    };
};



export const registerUser = async ({name, email, password}) => {
  const existingUser = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  if (existingUser.rows.length > 0) {
    throw new ApiError(409, "user already exists");
  }

  const passwordHash = await hashPassword(password);

  const { rowCount, rows: userRow } = await db.query(
    `INSERT INTO users (name, email, password_hash)
     VALUES ($1, $2, $3)
     RETURNING id, name, email, created_at`,
    [name, email, passwordHash],
  );
  if (rowCount === 0) {
    throw new ApiError(500, "Failed to register user");
  }
  const user = toPublicUser(userRow[0]);
  const tokens = await createUserTokens(user);
  return { user , tokens };
};

export const loginUser = async ({email, password}) => {
  const user = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  if (user.rows.length === 0) {
    throw new ApiError(404, "user not found");
  }
  const isMatch = await comparePassword(password, user.rows[0].password_hash);
  if (!isMatch) {
    throw new ApiError(401, "invalid password");
  }
  const tokens = await createUserTokens(user.rows[0]);
  return { user: toPublicUser(user.rows[0]) , tokens };
};

export const logoutUser = async (refreshToken) => {
    if (!refreshToken) return;

    const tokenHash = hashToken(refreshToken);

    await db.query(
        `UPDATE refresh_tokens
         SET revoked_at = NOW()
         WHERE token_hash = $1
         AND revoked_at IS NULL`,
        [tokenHash]
    );
};

export const refreshUserTokens = async (refreshToken) => {
    // 1. Verify JWT signature and expiration
    let decoded;

    try {
        decoded = verifyRefreshToken(refreshToken);
    } catch {
        throw new ApiError(401, "Invalid or expired refresh token");
    }

    const tokenHash = hashToken(refreshToken);

    // 2. Start transaction
    const client = await db.connect();

    try {
        await client.query("BEGIN");

        // 3. Find active refresh token and lock its row
        const result = await client.query(
            `SELECT
                rt.id AS refresh_token_id,
                rt.user_id,
                u.name,
                u.email,
                u.created_at
             FROM refresh_tokens rt
             JOIN users u ON u.id = rt.user_id
             WHERE rt.token_hash = $1
               AND rt.revoked_at IS NULL
               AND rt.expires_at > NOW()
             FOR UPDATE OF rt`,
            [tokenHash]
        );

        if (result.rows.length === 0) {
            throw new ApiError(401, "Refresh token revoked or not found");
        }

        const user = result.rows[0];

        // Make sure JWT belongs to the same user
        if (decoded.id !== user.user_id) {
            throw new ApiError(401, "Invalid refresh token");
        }

        // 4. Revoke old token
        await client.query(
            `UPDATE refresh_tokens
             SET revoked_at = NOW()
             WHERE id = $1`,
            [user.refresh_token_id]
        );

        // 5. Generate new tokens
        const publicUser = {
            id: user.user_id,
            name: user.name,
            email: user.email,
            created_at: user.created_at
        };

        const accessToken = generateAccessToken(publicUser);
        const newRefreshToken = generateRefreshToken(publicUser);

        // 6. Store new refresh token hash
        await client.query(
            `INSERT INTO refresh_tokens
             (user_id, token_hash, expires_at)
             VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
            [user.user_id, hashToken(newRefreshToken)]
        );

        // 7. Commit transaction
        await client.query("COMMIT");

        return {
            user: publicUser,
            tokens: {
                accessToken,
                refreshToken: newRefreshToken
            }
        };

    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
};



