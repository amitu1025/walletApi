const bip39 = require("bip39");
const { BIP32Factory } = require("bip32");
const { validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const bitcoin = require("bitcoinjs-lib");
const ecc = require("tiny-secp256k1");
const User = require("../Models/User.schema");
const newwallet = require("../middlewares/generateWallets");
const bip32 = BIP32Factory(ecc);
const { ECPairFactory } = require("ecpair");
const ECPair = ECPairFactory(ecc);
const bitcoinMessage = require("bitcoinjs-message");

const derivationPath = "m/44'/0'/0'/0/0";

class WalletController {
  static async generateMnenomic(req, res) {
    const mnemonic = bip39.generateMnemonic(256);
    try {
      return res.status(200).json({
        message: "Mnemonic generated Successfully",
        data: mnemonic,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  }

  static async registerUser(req, res) {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array() });
      }
      const { mnemonic, firstname, lastname, username } = req.body;
      const existinguser = await User.findOne({ mnemonic });

      if (existinguser) {
        return res.status(401).json({
          error:
            "This mnemonic is already registered with us, Please registering with another mnemonic.",
        });
      }
      const seed = await bip39.mnemonicToSeed(mnemonic); // converts mnemonic to seed
      const root = bip32.fromSeed(seed);
      const path = derivationPath; // BIP44 path for Bitcoin account 0, external chain
      const child = root.derivePath(path);
      const { address } = bitcoin.payments.p2pkh({ pubkey: child.publicKey });
      // Hash password
      // const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = new User({
        firstname,
        lastname,
        email: username,
        username,
        mnemonic,
        address,
        wallet: {
          publicKey: child.publicKey.toString("hex"),
          privateKey: child.toWIF(),
        },
      });
      // Save user to database
      await newUser.save();
      return res.status(200).json({
        message: "User Registered Successfully",
        data: mnemonic,
      });
    } catch (error) {
      console.log("error", error);
      res.status(500).json({
        error:
          "Something went wrong while registering, please try after some time.",
      });
    }
  }

  static async signin(req, res) {
    const {
      // username,
      // password,
      mnemonic,
    } = req.body;

    try {
      // Find user by mnemonic
      const arUser = await User.find({ mnemonic });
      const userDetail = arUser ? arUser[0] : undefined;
      if (!userDetail) {
        return res.status(401).json({
          error:
            "Invalid Mnemonic! Please enter the valid mnemonic to continue.",
        });
      }

      // const user = await User.findOne({ username });
      // if (!user) {
      //   return res.status(401).json({ error: "Invalid credentials" });
      // }

      // // Verify password
      // const passwordMatch = await bcrypt.compare(password, user.password);
      // if (!passwordMatch) {
      //   return res.status(401).json({ error: "Invalid credentials" });
      // }

      // Generate JWT token which expires in 8 hours
      const secretKey = process.env.PASSWORD_SECRET;
      const token = jwt.sign({ mnemonic }, secretKey, {
        expiresIn: "8h", // Token expiry time
      });

      return res.status(200).json({ token });
    } catch (error) {
      return res.status(500).json({ error: "Internal server error" });
    }
  }

  static async getLoggedInUser(req, res) {
    try {
      const { mnemonic } = req?.user;
      const arUser = await User.find({ mnemonic });
      const userDetail = arUser ? arUser : [];
      return res.status(200).json(userDetail);
    } catch (error) {
      return res.status(401).json({ error: "Unauthorized" });
    }
  }

  static async generateWallets(req, res) {
    try {
      const { noOfWallets, mnemonic } = req?.body;
      const wallets = newwallet.generateWallets(mnemonic, noOfWallets);
      // Update multiple wallets created
      const objUser = await User.findOneAndUpdate(
        { mnemonic },
        { $set: { wallet: wallets } }
      );
      return res.status(200).json({
        message: "Successfully generated address",
        data: objUser,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal Server Error" });
    }
  }

  // Create a message signature using private key
  static async generateMessageSignature(req, res) {
    try {
      const { message, privateKey } = req?.body;
      const keyPair = ECPair.fromWIF(privateKey);
      const signature = bitcoinMessage
        .sign(message, keyPair.privateKey, keyPair.compressed)
        .toString("base64");

      return res.status(200).json({
        message: "Successfully generated signature",
        signature: signature,
      });
    } catch (error) {
      console.log("error", error);
      res.status(500).json({ error: "Invalid private key or message" });
    }
  }

  static async verifyMessageSignature(req, res) {
    const { publicKey, signature, message } = req.body;
    try {
      const publicKeyBuffer = Buffer.from(publicKey, "hex");
      const signatureBuffer = Buffer.from(signature, "base64");
      const isValid = bitcoinMessage.verify(
        message,
        publicKeyBuffer,
        signatureBuffer
      );
      res.json({ isValid });
    } catch (error) {
      console.log("error", error);
      res
        .status(400)
        .json({ error: "Invalid public key, signature, or message" });
    }
  }
}

module.exports = WalletController;
