const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bip39 = require("bip39");
const mongoose = require("mongoose");
const bitcoin = require("bitcoinjs-lib");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
const path = require("path");
const User = require("./Models/User.schema");
const cors = require("cors");
require("dotenv").config({ path: path.resolve(process.cwd(), ".env") });
const verifyToken = require("./middlewares/verifyToken");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT;

// Connect to MongoDB
mongoose.connect(process.env.MONGO_DB_CONNECTION_STRING, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware for parsing JSON
app.use(bodyParser.json());

// Route for user registration
app.post("/register", async (req, res) => {
  const { firstname, lastname, username, password } = req.body;
  try {
    const mnemonic = bip39.generateMnemonic(); // generates mnemonic phrase
    const seed = await bip39.mnemonicToSeed(mnemonic); // converts mnemonic to seed
    const bip32 = BIP32Factory(ecc);
    const root = bip32.fromSeed(seed);
    const path = "m/44'/0'/0'/0/0"; // BIP44 path for Bitcoin account 0, external chain
    const child = root.derivePath(path);
    const { address } = bitcoin.payments.p2pkh({ pubkey: child.publicKey });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstname,
      lastname,
      email: username,
      username,
      mnemonic,
      address,
      password: hashedPassword,
      wallet: {
        publicKey: child.publicKey.toString("hex"),
        privateKey: child.toWIF(),
      },
    });

    // Save user to database
    await newUser.save();

    return res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.log("error", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Route for user login
app.post("/login", async (req, res) => {
  const { username, password, mnemonic } = req.body;

  try {
    // Find user by mnemonic
    // const usermnemonic = await User.findOne({ mnemonic });
    // if (!usermnemonic) {
    //   return res.status(401).json({ error: "Invalid Mnemonic" });
    // }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const secretKey = process.env.PASSWORD_SECRET;
    const token = jwt.sign({ username: user.username }, secretKey, {
      expiresIn: "8h",
    });

    return res.status(200).json({ token });
  } catch (error) {
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Protected route
app.get("/getallusers", verifyToken, async (req, res) => {
  try {
    const data = await User.find();
    return res.status(200).json(data);
  } catch (error) {
    return res.status(401).json({ error: "Unauthorized" });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
