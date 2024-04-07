const { body } = require("express-validator");

const validategenerateKeys = [
  body("mnemonic")
    .not()
    .isEmpty()
    .isString()
    .ltrim()
    .rtrim()
    // .whitelist(myWhitelist)
    .escape()
    .withMessage("Send your 24 characters long mnemonic words"),
];

module.exports = validategenerateKeys;
