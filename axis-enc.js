const jose = require('node-jose');

async function jweEncrypt(alg, contentKeyEncMethod, publicKey, payload) {
  const key = await jose.JWK.asKey(publicKey, 'pem');
  const payloadString = JSON.stringify(payload); // Convert object to JSON string
  const encrypted = await jose.JWE.createEncrypt({ format: 'compact' }, key)
    .update(payloadString) // Use the JSON string as payload
    .final();
  return encrypted;
}

async function jweDecrypt(privateKey, jweEncryptedPayload) {
  const key = await jose.JWK.asKey(privateKey, 'pem');
  const decrypted = await jose.JWE.createDecrypt(key)
    .update(jweEncryptedPayload)
    .final();
  return decrypted.payload.toString();
}

async function jwsSign(privateKey, payloadToSign) { 
  const key = await jose.JWK.asKey(privateKey, 'pem');
  const signed = await jose.JWS.createSign({ format: 'compact' }, key)
    .update(payloadToSign)
    .final();
  return signed;
}

async function jwsVerify(publicKey, signedPayloadToVerify) {
  const key = await jose.JWK.asKey(publicKey, 'pem');
  const verified = await jose.JWS.createVerify(key)
    .verify(signedPayloadToVerify);
  return verified.payload.toString();
}

async function jweEncryptAndSign(publicKeyToEncrypt, privateKeyToSign, payloadToEncryptAndSign) {
  const alg = 'RSA-256';
  const enc = '';
  const encryptedResult = await jweEncrypt(alg, enc, publicKeyToEncrypt, payloadToEncryptAndSign);
  const signedResult = await jwsSign(privateKeyToSign, encryptedResult);
  return signedResult;
}

async function jweVerifyAndDecrypt(publicKeyToVerify, privateKeyToDecrypt, payloadToVerifyAndDecrypt) {
    const verifiedPayload = await jwsVerify(publicKeyToVerify, payloadToVerifyAndDecrypt);
  
    try {
      // Parse the JWS payload to get the encrypted JWE payload
      const jwsObject = jose.JWS.parse(verifiedPayload);
      const encryptedPayload = jwsObject.payload;
  
      // Decrypt the JWE payload
      const decryptedResult = await jweDecrypt(privateKeyToDecrypt, encryptedPayload);
      return decryptedResult;
    } catch (error) {
      // Handle decryption error
      console.error('Decryption error:', error);
      return null;
    }
  }
  

// Example usage
const publicKeyToEncrypt = `-----BEGIN CERTIFICATE-----
MIIDcjCCAloCAQEwDQYJKoZIhvcNAQELBQAwgasxCzAJBgNVBAYTAklOMRQwEgYD
VQQIDAtNYWhhcmFzaHRyYTEPMA0GA1UEBwwGTXVtYmFpMRIwEAYDVQQKDAlBeGlz
IEJhbmsxETAPBgNVBAsMCEFQSSBUZWFtMSUwIwYDVQQDDBxVQVQgSW50ZXJtZWRp
YXRlIENlcnRpZmljYXRlMScwJQYJKoZIhvcNAQkBFhhhcGkuY29ubmVjdEBheGlz
YmFuay5jb20wHhcNMjQwMjE0MDcxMzM5WhcNMjUwMjAxMDcxMzM5WjBSMQswCQYD
VQQGEwJJTjEPMA0GA1UECAwGUHVuamFiMQ8wDQYDVQQHDAZNb2hhbGkxITAfBgNV
BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALgwx0l2lfZ4sYL6tOI8L5er67PsCMiw/XadTL8COwCqtB2C
mEvVM/+jWfh94f3/A2ijvfLxd4jR5zj3gRwgWCq8a++QFOnlkBuqWVZFhImIaMk7
q+PLy7ObF7hQ0dMCBW8BS80t0qpnS9+4GIx0yPTo133jE31YH6Dxl4jH37Wy2Qf8
8hz6XxzW2gPXSi5vkI/gRbWhoWe9ZOoSPA+vcYzj4OqA9aqGAZUqh4MJNA+YPYeC
8p+k6XJonI5CIazWYry3Tgsp7gw5fXAEht5LeoGMDhxEgrRyS9a8UKCfRoTb880O
TF36/XBvS7qTzfoTBzh0iC+VK7kmH6xBya0fzo0CAwEAATANBgkqhkiG9w0BAQsF
AAOCAQEAdwUhgwVv33XkgOZLzTNeslxT/ncA8xxB28LrfTnnkMlIzLSDav/ogS6+
HKat+7rsR6DtsLL5mRt1nexZHiGg9q3WotPFnRSYuJmJ3NUHSTo79Y0M/yWD140z
B+zzzG5ugXM7lJyyEu5Ls6Bb8iO9YOgw+x7HuJUoY3caUoJbmAh1Z3mXCW5w2qUr
tOedvcjpanHQiGL09pQvDeSQmPeKd5/QtF7mzPsnL0aCponabJG5cR6o4Q0NA4Rk
LWeZ7Dy137QGWo0hbTQD5EIqB69q9Dyo9Z3viOu5sPky5NDdSxN0tYtgpZpZsk9b
LOApv0snQKSfgLk1KewycNZKxk4HBA==
-----END CERTIFICATE-----`;


const privateKeyToSign = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,FACE0F585994EFB8F8F56043558DBDBA

WcU43cbI+/o6DI13gGfIvKsdyX87igXwwn0ruigA0uAIErX/pKN0B9XWCldBFSbP
u/JGLFCPr8DKlUGptF2iqFiNqTP7JOgUSjdsW27cP9fqJ3HhP1X+sMm+Zmi2j0Xl
gK67Ec4Ebl9ts6Ryr43FgUnCxRLgsisu8t+2WXhlCOncu7CXmXuUlAaqtrTBoiVk
P1dBCQ5vGKE1YLqHfaB2DjeUuvUnCXpBNK50gq7E8dL2NM+mLc26XyiNW7/uEjwW
O+F0hyu3RRAYrUmi1255/45IT/KR/uNqIfb6HnCL6Xl3jIc6I8A5YA0JsVssUnv/
U8fthkuqtYCxAN0dfaOJmo1hFCJUoZn4pNRImv2w+VBBBioMiws7Z49tjXniGNvx
PMveyZxtMkI5IniPAMSp07S4WC7NQDbrpTNbR5zbOp63km2PnKCmK2qNlPQfvK7v
9qxrTVwWjNTCwvkdLy5g33pKSaU8l6Z2V3igTVhIS9dBv3D9E46B4AT2hyrSlpEx
RIxjmrD9Skr3qKisAnYI94FD+KExv1NGQ1tRSKE3z5S6k5Src9HZqDr0/nlkkd+n
9ICCVcFbcZEiT15GBR/76oG0YdBL9cFqMsNQ1TeK8EQW51QNxRJS40avRQXx+Y5p
L9wUCSayXxHRhzjsF8k8fY5KD8Q3/GHmbVCH7+PrournC9yK8BIsQIi07G+HPR8j
V95GXFjqm7zBSPJdbdYbvNFaheUEB+ZR/wg4xhPlso+i2DgzsgDT8YayWkMc1Fvf
1jivnJR8BibpSS8WnPuj4z0pVvpD1YLSxAIxT7cwEwFGNtSror9fxGhNJedkMoeI
7g5D3zKmuoUlkCD0Tgd6FEZ62X+KyMxpxBJwxZ5J+OwatLRbS1bvKomBKocBjGTC
Rbe6kkfTmbm5Bjxb4cniJA+JDnebtkC+gMvCoF5smL4WcAL40uc8DwB3bMLBmkYv
eaCzRpApXIsJty9YKAQtmJJmKhSE2mi0pNXVTPJiFciMr+yYZpGobYIbmRuif1+C
AmOY7MOseV1f1eRu8LJkNEbYGFg42pSzzUtDy4SMGom2uIV5//gQoIGK+peek/tX
M50RQZwhadxMgQFVQQo772Zyg+sVsnpaX5MOsF7WrIKjtzQdAi21Hclp34kZBxNK
XzgqfMHqBM0ZkoFg2Q4YPZhup+kytCjEWNYeiTQr0+9l+pEgH/9gK7VI879XXSdI
MVx4xIgQoovcMfp2hWDGc5MJChfgVJMmIcSsiHEj+jEp70UiNsGnZU8gWGClN1h+
TcYxmTMHMxeyjF9MWz0FlYiN4FueodgX/EwSGNtdnfDLuzgY+TsdzQhmpYnTRlsw
gpPqDd1OrGEb3JRtAbJNx1QqGufyDVRfXxnPPJ1HV+eTyc8HopTE3vrP3H8QjEQ2
h/t1xxBS5Ht0VEofVHV7V0NrFcecD6EpXV183JUO4m6jx51HYh+7WzDSPTys1t56
X4uw0zzVv6BTcjh6AStirgcgH1lSYWvMaBN6Uh27uL2PPg9J1Y/mUBTAChgVCuzn
/jofh39ZC1o28d18JP/hOVyUtGHtP7MVewMJW+yWojPPPqpTSIiQ1rAbjRUzhvkG
-----END RSA PRIVATE KEY-----`;


const publicKeyToVerify = `-----BEGIN CERTIFICATE-----
MIIDcjCCAloCAQEwDQYJKoZIhvcNAQELBQAwgasxCzAJBgNVBAYTAklOMRQwEgYD
VQQIDAtNYWhhcmFzaHRyYTEPMA0GA1UEBwwGTXVtYmFpMRIwEAYDVQQKDAlBeGlz
IEJhbmsxETAPBgNVBAsMCEFQSSBUZWFtMSUwIwYDVQQDDBxVQVQgSW50ZXJtZWRp
YXRlIENlcnRpZmljYXRlMScwJQYJKoZIhvcNAQkBFhhhcGkuY29ubmVjdEBheGlz
YmFuay5jb20wHhcNMjQwMjE0MDcxMzM5WhcNMjUwMjAxMDcxMzM5WjBSMQswCQYD
VQQGEwJJTjEPMA0GA1UECAwGUHVuamFiMQ8wDQYDVQQHDAZNb2hhbGkxITAfBgNV
BAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALgwx0l2lfZ4sYL6tOI8L5er67PsCMiw/XadTL8COwCqtB2C
mEvVM/+jWfh94f3/A2ijvfLxd4jR5zj3gRwgWCq8a++QFOnlkBuqWVZFhImIaMk7
q+PLy7ObF7hQ0dMCBW8BS80t0qpnS9+4GIx0yPTo133jE31YH6Dxl4jH37Wy2Qf8
8hz6XxzW2gPXSi5vkI/gRbWhoWe9ZOoSPA+vcYzj4OqA9aqGAZUqh4MJNA+YPYeC
8p+k6XJonI5CIazWYry3Tgsp7gw5fXAEht5LeoGMDhxEgrRyS9a8UKCfRoTb880O
TF36/XBvS7qTzfoTBzh0iC+VK7kmH6xBya0fzo0CAwEAATANBgkqhkiG9w0BAQsF
AAOCAQEAdwUhgwVv33XkgOZLzTNeslxT/ncA8xxB28LrfTnnkMlIzLSDav/ogS6+
HKat+7rsR6DtsLL5mRt1nexZHiGg9q3WotPFnRSYuJmJ3NUHSTo79Y0M/yWD140z
B+zzzG5ugXM7lJyyEu5Ls6Bb8iO9YOgw+x7HuJUoY3caUoJbmAh1Z3mXCW5w2qUr
tOedvcjpanHQiGL09pQvDeSQmPeKd5/QtF7mzPsnL0aCponabJG5cR6o4Q0NA4Rk
LWeZ7Dy137QGWo0hbTQD5EIqB69q9Dyo9Z3viOu5sPky5NDdSxN0tYtgpZpZsk9b
LOApv0snQKSfgLk1KewycNZKxk4HBA==
-----END CERTIFICATE-----`;

const privateKeyToDecrypt = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,FACE0F585994EFB8F8F56043558DBDBA

WcU43cbI+/o6DI13gGfIvKsdyX87igXwwn0ruigA0uAIErX/pKN0B9XWCldBFSbP
u/JGLFCPr8DKlUGptF2iqFiNqTP7JOgUSjdsW27cP9fqJ3HhP1X+sMm+Zmi2j0Xl
gK67Ec4Ebl9ts6Ryr43FgUnCxRLgsisu8t+2WXhlCOncu7CXmXuUlAaqtrTBoiVk
P1dBCQ5vGKE1YLqHfaB2DjeUuvUnCXpBNK50gq7E8dL2NM+mLc26XyiNW7/uEjwW
O+F0hyu3RRAYrUmi1255/45IT/KR/uNqIfb6HnCL6Xl3jIc6I8A5YA0JsVssUnv/
U8fthkuqtYCxAN0dfaOJmo1hFCJUoZn4pNRImv2w+VBBBioMiws7Z49tjXniGNvx
PMveyZxtMkI5IniPAMSp07S4WC7NQDbrpTNbR5zbOp63km2PnKCmK2qNlPQfvK7v
9qxrTVwWjNTCwvkdLy5g33pKSaU8l6Z2V3igTVhIS9dBv3D9E46B4AT2hyrSlpEx
RIxjmrD9Skr3qKisAnYI94FD+KExv1NGQ1tRSKE3z5S6k5Src9HZqDr0/nlkkd+n
9ICCVcFbcZEiT15GBR/76oG0YdBL9cFqMsNQ1TeK8EQW51QNxRJS40avRQXx+Y5p
L9wUCSayXxHRhzjsF8k8fY5KD8Q3/GHmbVCH7+PrournC9yK8BIsQIi07G+HPR8j
V95GXFjqm7zBSPJdbdYbvNFaheUEB+ZR/wg4xhPlso+i2DgzsgDT8YayWkMc1Fvf
1jivnJR8BibpSS8WnPuj4z0pVvpD1YLSxAIxT7cwEwFGNtSror9fxGhNJedkMoeI
7g5D3zKmuoUlkCD0Tgd6FEZ62X+KyMxpxBJwxZ5J+OwatLRbS1bvKomBKocBjGTC
Rbe6kkfTmbm5Bjxb4cniJA+JDnebtkC+gMvCoF5smL4WcAL40uc8DwB3bMLBmkYv
eaCzRpApXIsJty9YKAQtmJJmKhSE2mi0pNXVTPJiFciMr+yYZpGobYIbmRuif1+C
AmOY7MOseV1f1eRu8LJkNEbYGFg42pSzzUtDy4SMGom2uIV5//gQoIGK+peek/tX
M50RQZwhadxMgQFVQQo772Zyg+sVsnpaX5MOsF7WrIKjtzQdAi21Hclp34kZBxNK
XzgqfMHqBM0ZkoFg2Q4YPZhup+kytCjEWNYeiTQr0+9l+pEgH/9gK7VI879XXSdI
MVx4xIgQoovcMfp2hWDGc5MJChfgVJMmIcSsiHEj+jEp70UiNsGnZU8gWGClN1h+
TcYxmTMHMxeyjF9MWz0FlYiN4FueodgX/EwSGNtdnfDLuzgY+TsdzQhmpYnTRlsw
gpPqDd1OrGEb3JRtAbJNx1QqGufyDVRfXxnPPJ1HV+eTyc8HopTE3vrP3H8QjEQ2
h/t1xxBS5Ht0VEofVHV7V0NrFcecD6EpXV183JUO4m6jx51HYh+7WzDSPTys1t56
X4uw0zzVv6BTcjh6AStirgcgH1lSYWvMaBN6Uh27uL2PPg9J1Y/mUBTAChgVCuzn
/jofh39ZC1o28d18JP/hOVyUtGHtP7MVewMJW+yWojPPPqpTSIiQ1rAbjRUzhvkG
-----END RSA PRIVATE KEY-----`;

const payloadToEncryptAndSign = {
    "Data": {
      "userName": "alwebuser",
      "password": "acid_qa"
    },
    "Risks": {}
  };

jweEncryptAndSign(publicKeyToEncrypt, privateKeyToSign, payloadToEncryptAndSign)
  .then(signedResult => {
    console.log('Encrypted and Signed:', signedResult);

    // Example: Verify and Decrypt
    jweVerifyAndDecrypt(publicKeyToVerify, privateKeyToDecrypt, signedResult)
      .then(decryptedResult => {
        console.log('Decrypted Result:', decryptedResult);
      })
      .catch(error => {
        console.error('Verification and Decryption error:', error);
      });
  })
  .catch(error => {
    console.error('Encryption and Signing error:', error);
  });
