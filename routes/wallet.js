const express = require("express");
const WalletController = require("../controllers/walletController.js");
const validategenerateKeys = require("../utils/validator/wallet.js");
const verifyToken = require("../middlewares/verifyToken.js");

const router = express.Router();

// Generate mnemonic phrase
router.get("/generateMnenomic", WalletController.generateMnenomic);

// Register by generating mnemonic phrase and user details
router.post("/register", validategenerateKeys, WalletController.registerUser);
// Login using mnemonic phrase
router.post("/login", WalletController.signin);

// Create multiple wallets using mnemonics phrase
router.post("/create-wallets", WalletController.generateWallets);

// Generate message signature using private key
router.post("/generate-signature", WalletController.generateMessageSignature);

// Verify message signature using public key
router.post("/verify-signature", WalletController.verifyMessageSignature);

// only authenticated user can access this route path
router.post("/getloggedinuser", verifyToken, WalletController.getLoggedInUser);

module.exports = router;
