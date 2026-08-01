# JWT verification and generation

Verify and create JWTs using async webcrypto.

ES256 (ECDSA with P-256 and SHA-256) and RS256 (RSA with SHA-256)

The package is split into three subpath exports:

- `@dwbinns/jwt/generate` — private key import and JWT signing
- `@dwbinns/jwt/verify` — public key import and JWT verification
- `@dwbinns/jwt/info` — parsing and expiry helpers (no keys required)

```js
import { create, importPrivateKey } from "@dwbinns/jwt/generate";
import { verify, importPublicKey } from "@dwbinns/jwt/verify";
import { expiredTime, expiredFraction } from "@dwbinns/jwt/info";

const jwk = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
    "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
};

const key = await importPrivateKey("ES256", "kid", jwk);
const publicKey = await importPublicKey("ES256", "kid", jwk);

const jwt = await create(key, {sub: "me", ...expiredTime(3600)});
console.log("JWT:", jwt);
console.log(`Expired: ${expiredFraction(jwt) * 100}%`);
const claims = await verify(publicKey, jwt);
console.log("Subject:", claims.sub); 
console.log("Expires:", new Date(claims.exp * 1e3));
try {
    await verify(publicKey, "eyJraWQiOiJraWQiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSJ9.invalid");
} catch (e) {
    console.log("Verification error:", e.message);
}
```

```
JWT: eyJraWQiOiJraWQiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImlhdCI6MTcxODY0MDk4NywiZXhwIjoxNzE4NjQ0NTg3fQ.fNZx8X2p7AFrlN7RSnr0n3rnxVjN6raBbDZhEbiWNomRFofG2KXFX8AwRHtXTa86VNxR8wOXnNVnly80IMP2CA
Expired: 0.004611111111111112%
Subject: me
Expires: 2024-06-17T17:16:27.000Z
Verification error: JWT not valid
```

## `@dwbinns/jwt/info`

### parse
```javascript
function parse(text)
```
Synchronously parse a JWT without verification
```javascript
import { parse } from "@dwbinns/jwt/info";
console.log(parse("eyJraWQiOiJraWQiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImlhdCI6MTcxODY0MDk4NywiZXhwIjoxNzE4NjQ0NTg3fQ.fNZx8X2p7AFrlN7RSnr0n3rnxVjN6raBbDZhEbiWNomRFofG2KXFX8AwRHtXTa86VNxR8wOXnNVnly80IMP2CA"));
```
Returns all parts of the JWT, decoded:
```
{
  header: { kid: 'kid', alg: 'ES256' },
  claims: { sub: 'me', iat: 1718640987, exp: 1718644587 },
  signature: Uint8Array(64) [
    124, 214, 113, 241, 125, 169, 236,   1, 107, 148, 222,
    209,  74, 122, 244, 159, 122, 231, 197,  88, 205, 234,
    182, 129, 108,  54,  97,  17, 184, 150,  54, 137, 145,
     22, 135, 198, 216, 165, 197,  95, 192,  48,  68, 123,
     87,  77, 175,  58,  84, 220,  81, 243,   3, 151, 156,
    213, 103, 151,  47,  52,  32, 195, 246,   8
  ],
  signed: 'eyJraWQiOiJraWQiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJtZSIsImlhdCI6MTcxODY0MDk4NywiZXhwIjoxNzE4NjQ0NTg3fQ'
}
```

### expiredTime
```javascript
function expiredTime(durationSeconds)
```
Create claims that are issued now and expire in `durationSeconds`

### expiredFraction
```javascript
function expiredFraction(jwt, createdAt, now = new Date())
```

Return what fraction of a JWT has expired. 
Will be less than 0 if the JWT is not yet valid and more than 1 if it has expired.
Optionally supply a `createdAt` Date object representing when the JWT was created. 
If supplied then clock skew will not affect the result. 
If not supplied the `iat` field of the JWT will by used instead.
Supply a `now` Date object to check the expiry status of a JWT at some other point of time.

## `@dwbinns/jwt/generate`

### importPrivateKey
```javascript
async function importPrivateKey(jwk)
async function importPrivateKey(alg, kid, jwk)
```
Import a private key from a JWK, returning a `PrivateKeyEntry`. The JWK must contain the private component (`d`).
With the single-argument form the JWK must contain `alg` and `kid` fields.

### importPemPrivateKey
```javascript
async function importPemPrivateKey(alg, kid, pem)
```
Import a private key from a PEM string. Supports pkcs8 private keys (`BEGIN PRIVATE KEY`).
For `BEGIN RSA PRIVATE KEY` (pkcs1) convert first:
```
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs1.key -out pkcs8.key
```

### create
```javascript
async function create(key, claims)
```
Create (sign) a JWT using a single `PrivateKeyEntry` and the supplied `claims`. See first example.

## `@dwbinns/jwt/verify`

### verify
```javascript
async function verify(keys, text, now = new Date())
```

Parse and verify a JWT, throwing an error if the JWT is expired, not yet valid or does not have a valid signature.
Keys should be a `PublicKeyEntry` or an array of them, created via one of the import functions.
Returns the JWT's claims, see first example.

### importPublicKey
```javascript
async function importPublicKey(alg, kid, jwk)
```
Import a public key from a JWK, returning a `PublicKeyEntry`. Any private component is stripped before import.

### importPemPublicKey
```javascript
async function importPemPublicKey(alg, kid, pem)
```
Import a public key from a PEM string. Supports spki public keys (`BEGIN PUBLIC KEY`).

### importHostJWKS
```javascript
function importHostJWKS(hostname)
```
Import all keys from a key set for a host

### importURLJWKS
```javascript
async function importURLJWKS(url)
```
Import all keys from a key set from a URL

### importJWKS
```javascript
async function importJWKS({ keys })
```
Import all keys from a key set
