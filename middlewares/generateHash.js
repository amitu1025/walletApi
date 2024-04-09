const crypto = require("crypto");

const generateHash = (secret_key) => {
  return crypto
    .createHash("sha512")
    .update(secret_key)
    .digest("hex")
    .substring(0, 32);
};

module.exports = generateHash;
