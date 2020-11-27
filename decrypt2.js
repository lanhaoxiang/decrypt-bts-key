const { PublicKey, PrivateKey, Aes, Signature } = require('bitsharesjs');
const { decompress } = require('lzma');
const fs = require('fs');
var PASSWORD = '123123123';
var contents = fs.readFileSync('./test.bin', 'binary');
contents = Buffer.from(contents, 'binary');
// console.log();
// contents = contents.toString('hex');
const PREFIX = 'GXC';
const MESSAGE_TO_SIGN = 'DACPLAY: Verification Test';

let public_key = PublicKey.fromBuffer(contents.slice(0, 33));
let private_key = PrivateKey.fromSeed(PASSWORD); // the key used to encrypt binary, not the wallet key
var backup_buffer = contents.slice(33);
try {
  backup_buffer = Aes.decrypt_with_checksum(
    private_key,
    public_key,
    null /*nonce*/,
    backup_buffer
  );
} catch (error) {
  console.error('Error decrypting wallet', error, error.stack);
}

let output = [];

try {
  decompress(backup_buffer, (wallet_string) => {
    try {
      let wallet_object = JSON.parse(wallet_string);
      //   console.log(wallet_object);
      let wallet = wallet_object.wallet[0];
      let password_aes = Aes.fromSeed(PASSWORD);
      let encryption_plainbuffer = password_aes.decryptHexToBuffer(
        wallet.encryption_key
      );
      let password_private = PrivateKey.fromSeed(PASSWORD);
      let password_pubkey = password_private.toPublicKey().toString(PREFIX);
      if (wallet.password_pubkey !== password_pubkey) {
        console.error(
          'wrong password',
          password_pubkey,
          '!=',
          wallet.password_pubkey
        );
        return;
      }
      let aes_private = Aes.fromSeed(encryption_plainbuffer);
      wallet_object.private_keys.forEach((item) => {
        // console.log(item);
        let wifKey = aes_private.decryptHexToText(item.encrypted_key, 'hex');
        let priv_key = PrivateKey.fromHex(wifKey);
        let signed_hashed_msg = Signature.sign(
          MESSAGE_TO_SIGN,
          priv_key
        ).toHex();
        let signed_hex_msg = Signature.signHex(
          Buffer.from(MESSAGE_TO_SIGN).toString('hex'),
          priv_key
        ).toHex();
        output.push({
          public_key: priv_key.toPublicKey().toString(PREFIX),
          private_plainhex: priv_key.toHex(),
          private_key: priv_key.toWif(),
          message: MESSAGE_TO_SIGN,
          signed_hashed_msg,
          signed_hex_msg,
        });
      });
      console.log('\n\n\n\n============================');
      console.log(output);
      console.log('============================');
    } catch (error) {
      if (!wallet_string) wallet_string = '';
      console.error('Error parsing wallet json', error);
    }
  });
} catch (error) {
  console.error('Error decompressing wallet', error, error.stack);
}
