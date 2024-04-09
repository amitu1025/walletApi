const crypto = require("crypto");
const encryptionIV = require("./encryptionIV");
const config = require("../config");

const decryptAES = (encryptedData, key) => {
  const { secret_iv, ecnryption_method } = config;
  const IV = encryptionIV(secret_iv);
  const buff = Buffer.from(encryptedData, "base64");
  const decipher = crypto.createDecipheriv(ecnryption_method, key, IV);
  // Decrypts data and converts to utf8
  return (
    decipher.update(buff.toString("utf8"), "hex", "utf8") +
    decipher.final("utf8")
  );
};

module.exports = decryptAES;
