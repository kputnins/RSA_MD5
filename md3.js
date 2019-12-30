/* global BigInt */
const crypto = require('crypto');

// Generates the public and private RSA keys
const generateRSAKeys = (primeOne = 197, primeTwo = 199) => {
  const p = primeOne;
  const q = primeTwo;
  const n = p * q;
  const phi = (p - 1) * (q - 1);
  let e = 3;
  let d = 0;

  // Check if e is a factor of phi and increment it otherwise
  while (phi % e === 0) {
    e += 1;
  }

  // Naive solution to get d, so horrible time complexity ;)
  while ((e * d) % phi !== 1) {
    d += e;
  }

  return { publicKey: { e, n }, privateKey: { d, n } };
};

// Encrypts/Decrypts a message based on the RSA key provided
// Numbers cast as BigInt instead of int as the computations
// can exceed the max length of Number in JavaScript
const RSATransform = (msg, key) => {
  const { e, d, n } = key;
  const exp = e || d;
  const transMsg = BigInt(msg) ** BigInt(exp) % BigInt(n);

  return Number(transMsg);
};

// Creates a message by converting the message text
// and the MD5 hash to an array of ASCII codes
// The MD5 hash is encrypted using RSA and the provided key
const createMessage = (msg, key) => {
  const message = [];

  const hash = crypto
    .createHash('md5')
    .update(msg, 'utf8')
    .digest('hex');

  // Splits a word in to characters and for each character converts it to the ASCI code
  // and saves it as an entry in an array
  msg.split('').forEach(char => {
    message.push(char.charCodeAt());
  });

  // The same for the hash, but encrypts each ASCI code using RSA
  hash.split('').forEach(char => {
    message.push(RSATransform(char.charCodeAt(), key));
  });

  return { msg: message, hash };
};

// Parses a message which is an array of ASCII codes
// for the message + an encrypted MD5 hash as the last 32 characters
const parseMessage = (msg, key) => {
  let message = '';
  let hash = '';

  // Separates the message form the MS5 hash
  const hashCodes = msg.slice(-32);
  const msgCodes = msg.slice(0, msg.length - hashCodes.length);

  // For each ASCI code Converts it to the corresponding character
  // and appends it to a string
  msgCodes.forEach(code => {
    message += String.fromCharCode(code);
  });

  // The same for the hash, but decrypts each MD5 ASCII code using RSA
  hashCodes.forEach(code => {
    hash += String.fromCharCode(RSATransform(code, key));
  });

  // Checks if the received message generates the same MD5 hash as the received one
  const MD5Hash = crypto
    .createHash('md5')
    .update(message, 'utf8')
    .digest('hex');
  try {
    if (MD5Hash !== hash) {
      const error = {
        'Error message': 'received incorrect message - the generated MD5 hash does not match the received one',
        'Received Hash': MD5Hash,
        'Generated Hash': hash,
      };
      throw error;
    }
  } catch (error) {
    console.log('Error receiving the message', error);
  }

  return { message, hash: MD5Hash };
};

// Message to send
const message = 'KINO';

// Generated RSA keys
// Default primes 197 and 199
const { publicKey, privateKey } = generateRSAKeys();

// If all is OK scenario
const sentMessage = createMessage(message, publicKey);
const receivedMessage = parseMessage(sentMessage.msg, privateKey);
console.log('Sent message:     ', { message, hash: sentMessage.hash });
console.log('Received message: ', receivedMessage);
console.log();

// If message gets changed scenario
const sentMessage2 = createMessage(message, publicKey);
sentMessage2.msg[1] = 70;
const receivedMessage2 = parseMessage(sentMessage2.msg, privateKey);
console.log('Sent message:     ', { message, hash: sentMessage2.hash });
console.log('Received message: ', receivedMessage2);
