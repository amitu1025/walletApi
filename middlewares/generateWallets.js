const bitcoin = require("bitcoinjs-lib");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
const bip32 = BIP32Factory(ecc);

// Generate multiple wallets from the mnemonic
const generateWallets = (mnemonic, numWallets) => {
  const wallets = [];

  const seed = bitcoin.crypto.sha256(Buffer.from(mnemonic));
  const masterNode = bip32.fromSeed(seed);

  for (let i = 0; i < numWallets; i++) {
    // by adding the nos in the last node we can create a wallet in bitcoin
    const path = `m/44'/0'/0'/0/${i}`;
    const child = masterNode.derivePath(path);
    const { address } = bitcoin.payments.p2pkh({ pubkey: child.publicKey });
    wallets.push({
      publicKey: child.publicKey.toString("hex"),
      address,
      privateKey: child.toWIF(),
    });
  }
  return wallets;
};

module.exports = { generateWallets };
