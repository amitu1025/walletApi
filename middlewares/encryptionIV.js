const crypto = require("crypto");

const encryptionIV = (secret_iv) => {
  return crypto
    .createHash("sha512")
    .update(secret_iv)
    .digest("hex")
    .substring(0, 16);
};

module.exports = encryptionIV;
