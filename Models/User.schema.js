const mongoose = require("mongoose");

// Define user schema
const userSchema = new mongoose.Schema({
  firstname: { type: String, required: false },
  lastname: { type: String, required: false },
  email: { type: String, required: false },
  username: { type: String, required: false, unique: false },
  mnemonic: { type: String, required: false },
  address: { type: String, required: false },
  password: { type: String, required: false },
  wallet: {
    privateKey: String,
    publicKey: String,
  },
});

// Compile into a model
module.exports = mongoose.model("User", userSchema);
