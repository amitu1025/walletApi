const express = require("express");
const wallet = require("./wallet");

const router = express.Router();

router.use("/wallet", wallet);

module.exports = router;
