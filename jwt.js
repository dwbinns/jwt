// https://datatracker.ietf.org/doc/html/rfc7519

import * as b64 from "@dwbinns/base/64";
import * as b64url from "@dwbinns/base/64url";

const algorithms = {
    "RS256": {
        importKeyParams: {
            name: 'RSASSA-PKCS1-v1_5',
            hash: "SHA-256",
        },
        signatureParams: {
            name: 'RSASSA-PKCS1-v1_5',
        },

    },
    "ES256": {
        importKeyParams: {
            name: "ECDSA",
            namedCurve: "P-256",
        },
        signatureParams: {
            name: "ECDSA",
            hash: "SHA-256",
        }
    }
}


export function parse(text) {
    let [headerEncoded, claimsEncoded, signatureEncoded] = text.trim().split(".");
    let header = JSON.parse(b64url.decodeText(headerEncoded));
    let claims = JSON.parse(b64url.decodeText(claimsEncoded));
    let signature = b64url.decode(signatureEncoded);
    let signed = `${headerEncoded}.${claimsEncoded}`;
    return { header, claims, signature, signed };
}


export async function verify(keys, text, now = new Date()) {
    let { header, claims, signature, signed } = parse(text);

    for (let key of Array.isArray(keys) ? keys : [keys]) {

        let { alg, kid, publicKey } = key;

        let { signatureParams } = getParameters(alg);

        if (header.kid != kid || header.alg != alg) {
            continue;
        }

        let valid = await crypto.subtle.verify(
            signatureParams,
            publicKey,
            signature,
            new TextEncoder().encode(signed)
        );

        if (!valid) {
            throw new Error("JWT not valid");
        }

        let epochSeconds = now.getTime() / 1e3;

        if (claims.exp) {
            let epochSeconds = now.getTime() / 1e3;
            if (claims.exp < epochSeconds) {
                throw new Error("JWT expired")
            }
        }

        if (claims.iat) {

            if (claims.iat > epochSeconds) {
                throw new Error("JWT not yet valid")
            }
        }

        return claims;
    }

    throw new Error("Key not known");
}

function getParameters(alg) {
    let parameters = algorithms[alg];
    if (!parameters) {
        throw new Error("Unknown algorithm: " + alg);
    }
    return parameters;
}


export async function importPem(alg, kid, pem) {
    let lines = pem.split("\n").map(line => line.trim()).filter(Boolean);
    let title = lines[0].replaceAll("-", "").trim();

    let { importKeyParams } = getParameters(alg);

    // For BEGIN RSA PRIVATE KEY use:
    // openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs1.key -out pkcs8.key

    let privateKey = title == "BEGIN PRIVATE KEY" && await crypto.subtle.importKey(
        "pkcs8",
        b64.decode(lines.filter(line => !line.startsWith("--")).join("")),
        importKeyParams,
        true,
        ["sign"]
    );

    let publicKey = title == "BEGIN PUBLIC KEY" && await crypto.subtle.importKey(
        "spki",
        b64.decode(lines.filter(line => !line.startsWith("--")).join("")),
        importKeyParams,
        true,
        ["verify"]
    );

    if (privateKey) {
        let privateJWK = await crypto.subtle.exportKey("jwk", privateKey);
        let publicJWK = { ...privateJWK, d: undefined, dp: undefined, dq: undefined, q: undefined, qi: undefined, key_ops: undefined };
        publicKey = await crypto.subtle.importKey("jwk", publicJWK, importKeyParams, true, ["verify"]);
    }

    return [{ alg, kid, privateKey, publicKey }];
}

export async function importHostJWKS(hostname) {
    return await importURLJWKS(new URL(`https://${hostname}./well-known/jwks.json`));
}

export async function importURLJWKS(url) {
    let response = await fetch(url)
    if (!response.ok) throw new Error("JWKS fetch failed");

    return await importJWKS(await response.json());
}

async function importPublic(alg, jwk) {
    let { importKeyParams } = getParameters(alg);
    let publicJWK = { ...jwk, d: undefined, dp: undefined, dq: undefined, q: undefined, qi: undefined };
    return await crypto.subtle.importKey("jwk", publicJWK, importKeyParams, true, ["verify"]);
}

export async function importJWKS({ keys }) {
    return await Promise.all(keys.map(async ({ alg, kid, ...jwk }) => {
        if (!alg) return null;
        let publicKey = await importPublic(alg, jwk);
        return { alg, kid, publicKey };
    }));
}

export async function importJWK(alg, kid, jwk) {
    let { importKeyParams } = getParameters(alg);

    let privateKey = jwk.d && await crypto.subtle.importKey("jwk", jwk, importKeyParams, true, ["sign"]);
    let publicKey = await importPublic(alg, jwk);
    return [{ alg, kid, privateKey, publicKey }];
}

export function expiresTime(durationSeconds) {
    let now = Math.floor(Date.now() / 1e3);
    return {
        iat: now,
        exp: now + durationSeconds,
    };
}

export function expiredFraction(jwt, createdAt, now = new Date()) {
    const { claims } = parse(jwt);
    let { exp, iat } = claims;
    if (!exp) {
        return 0;
    }
    if (!iat && !createdAt) {
        throw new Error("No creation time or issued time available");
    }
    const created = createdAt ? createdAt.getTime() / 1e3 : iat;
    const issuedAt = iat || createdAt.getTime() / 1e3;
    return (now.getTime() / 1e3 - created) / (exp - issuedAt);
}

export async function create(keys, claims) {
    let key = Array.isArray(keys) ? keys.filter(({ privateKey }) => privateKey).at(0) : keys;
    if (!key) throw new Error("No private key supplied");
    let { alg, kid, privateKey } = key;
    let { signatureParams } = getParameters(alg);

    let header = { kid, alg };
    let headerEncoded = b64url.encodeText(JSON.stringify(header));
    let claimsEncoded = b64url.encodeText(JSON.stringify(claims));

    let signatureEncoded = b64url.encode(await crypto.subtle.sign(
        signatureParams,
        privateKey,
        new TextEncoder().encode(`${headerEncoded}.${claimsEncoded}`)
    ));
    return `${headerEncoded}.${claimsEncoded}.${signatureEncoded}`;
}
