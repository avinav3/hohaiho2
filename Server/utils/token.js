const jwt = require("jsonwebtoken");

const ACCESS_TOKEN_EXPIRES_IN = "15m";
const REFRESH_TOKEN_EXPIRES_IN = "7d";
const ACCESS_COOKIE_NAME = "accessToken";
const REFRESH_COOKIE_NAME = "refreshToken";

function getAccessTokenSecret() {
  return process.env.JWT_ACCESS_SECRET || "local-access-secret-change-me";
}

function getRefreshTokenSecret() {
  return process.env.JWT_REFRESH_SECRET || "local-refresh-secret-change-me";
}

function buildAuthPayload(account, accountType) {
  return {
    id: account._id.toString(),
    email: account.email,
    role: account.role || (accountType === "admin" ? "admin" : "user"),
    accountType,
  };
}

function generateAccessToken(payload) {
  return jwt.sign(payload, getAccessTokenSecret(), {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, getRefreshTokenSecret(), {
    expiresIn: REFRESH_TOKEN_EXPIRES_IN,
  });
}

function verifyAccessToken(token) {
  return jwt.verify(token, getAccessTokenSecret());
}

function verifyRefreshToken(token) {
  return jwt.verify(token, getRefreshTokenSecret());
}

function getRefreshTokenCookieOptions() {
  const isProduction = process.env.NODE_ENV === "production";

  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };
}

function getAccessTokenCookieOptions() {
  const isProduction = process.env.NODE_ENV === "production";

  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: 15 * 60 * 1000,
  };
}

function setAccessTokenCookie(res, accessToken) {
  res.cookie(ACCESS_COOKIE_NAME, accessToken, getAccessTokenCookieOptions());
}

function clearAccessTokenCookie(res) {
  res.clearCookie(ACCESS_COOKIE_NAME, getAccessTokenCookieOptions());
}

function setRefreshTokenCookie(res, refreshToken) {
  res.cookie(
    REFRESH_COOKIE_NAME,
    refreshToken,
    getRefreshTokenCookieOptions()
  );
}

function clearRefreshTokenCookie(res) {
  res.clearCookie(REFRESH_COOKIE_NAME, getRefreshTokenCookieOptions());
}

module.exports = {
  ACCESS_TOKEN_EXPIRES_IN,
  REFRESH_TOKEN_EXPIRES_IN,
  ACCESS_COOKIE_NAME,
  REFRESH_COOKIE_NAME,
  buildAuthPayload,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  setAccessTokenCookie,
  clearAccessTokenCookie,
  setRefreshTokenCookie,
  clearRefreshTokenCookie,
};
