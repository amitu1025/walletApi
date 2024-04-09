const crypto = require("crypto");
const config = require("../config");
const encryptionIV = require("./encryptionIV");

const encryptAES = (data, key) => {
  const { secret_key, secret_iv, ecnryption_method } = config;

  if (!secret_key || !secret_iv || !ecnryption_method) {
    throw new Error("secretKey, secretIV, and ecnryptionMethod are required");
  }
  const IV = encryptionIV(secret_iv);
  const cipher = crypto.createCipheriv(ecnryption_method, key, IV);
  return Buffer.from(
    cipher.update(data, "utf8", "hex") + cipher.final("hex")
  ).toString("base64");
};

module.exports = encryptAES;
