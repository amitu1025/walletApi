const dotenv = require("dotenv");

dotenv.config();

const { NODE_ENV, PORT, PASSWORD_SECRET, SECRET_IV, ECNRYPTION_METHOD } =
  process.env;

const data = {
  env: NODE_ENV,
  port: PORT,
  secret_key: PASSWORD_SECRET,
  secret_iv: SECRET_IV,
  ecnryption_method: ECNRYPTION_METHOD,
};

module.exports = data;
