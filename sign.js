const { PrivateKey, Signature } = require('bitsharesjs');

// The private key is random, take it easy
let private_key = PrivateKey.fromWif(
  '5JKf2SExDoSBJqpYGwScSvqqtBo5GAsFtcDgkRct9nyQ2D8QuMd'
);
let message = 'DACPLAY: Verification Test';

let signedHashedMsg = Signature.sign(message, private_key).toHex();
let signedHexMsg = Signature.signHex(
  Buffer.from(message).toString('hex'),
  private_key
).toHex();
console.log({ signedHashedMsg, signedHexMsg });

let verifySignedHashedMsg = Signature.fromHex(signedHashedMsg).verifyBuffer(
  message,
  private_key.toPublicKey()
);
let verifySignedHexMsg = Signature.fromHex(signedHexMsg).verifyHex(
  Buffer.from(message).toString('hex'),
  private_key.toPublicKey()
);

console.log({ verifySignedHashedMsg, verifySignedHexMsg });
