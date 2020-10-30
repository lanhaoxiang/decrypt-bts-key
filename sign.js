const { PrivateKey, Signature } = require('bitsharesjs');

// The private key is random, take it easy
let private_key = PrivateKey.fromWif(
  '5JKf2SExDoSBJqpYGwScSvqqtBo5GAsFtcDgkRct9nyQ2D8QuMd'
);
let message = 'DACPLAY: Verification Test';

let signedHashedMsg = Signature.sign(message, private_key).toHex();
let signedHexMsg = Signature.signHex(message, private_key).toHex();
console.log({ signedHashedMsg, signedHexMsg });
