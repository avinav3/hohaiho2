const { ACCESS_COOKIE_NAME, verifyAccessToken } = require("../utils/token");

function authenticateAccessToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const bearerToken = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : null;
  const cookieToken = req.cookies?.[ACCESS_COOKIE_NAME];
  const token = bearerToken || cookieToken;

  if (!token) {
    return res
      .status(401)
      .json({ flag: "0", message: "Access token is required." });
  }

  try {
    req.auth = verifyAccessToken(token);
    return next();
  } catch (error) {
    return res
      .status(401)
      .json({ flag: "0", message: "Invalid or expired access token." });
  }
}

function requireAdmin(req, res, next) {
  if (req.auth?.role !== "admin") {
    return res
      .status(403)
      .json({ flag: "0", message: "Admin access is required." });
  }

  return next();
}

module.exports = {
  authenticateAccessToken,
  requireAdmin,
};
