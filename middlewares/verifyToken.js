const jwt = require("jsonwebtoken");

// Middleware function to verify JWT token
const verifyToken = (req, res, next) => {
  // Get token from headers
  const token = req?.headers?.authorization;

  // Check if token exists
  if (!token) {
    return res.status(401).json({ message: "No token provided" });
  }

  // Verify token
  jwt.verify(token, process.env.PASSWORD_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Failed to authenticate token" });
    }

    // Attach decoded token payload to request object for further use
    req.user = decoded;

    // Move to the next middleware or route handler
    next();
  });
};

module.exports = verifyToken;
