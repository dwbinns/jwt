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
    return { header, claims, signature };
}


export async function verify(key, text) {
    let [headerEncoded, claimsEncoded, signatureEncoded] = text.trim().split(".");
    let header = JSON.parse(b64url.decodeText(headerEncoded));
    let claims = JSON.parse(b64url.decodeText(claimsEncoded));
    let signature = b64url.decode(signatureEncoded);

    if (key) {
        let { alg, kid, publicKey, } = key;
        let { signatureParams } = getParameters(alg);

        if (header.kid != kid || header.alg != alg) {
            throw new Error("Header not set correctly");
        }

        let valid = await crypto.subtle.verify(
            signatureParams,
            publicKey,
            signature,
            new TextEncoder().encode(`${headerEncoded}.${claimsEncoded}`)
        );

        if (!valid) {
            throw new Error("JWT not valid");
        }
    }

    return claims;
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
        let publicJWK = {...privateJWK, d: undefined, dp: undefined, dq: undefined, q: undefined, qi: undefined, key_ops: undefined};
        publicKey = await crypto.subtle.importKey("jwk", publicJWK, importKeyParams, true, ["verify"]);
    }

    return { alg, kid, privateKey, publicKey };
}

export async function importJWK(alg, kid, jwk) {
    let { importKeyParams } = getParameters(alg);

    let privateKey = jwk.d && await crypto.subtle.importKey("jwk", jwk, importKeyParams, true, ["sign"]);
    let publicJWK = {...jwk, d: undefined, dp: undefined, dq: undefined, q: undefined, qi: undefined};
    let publicKey = await crypto.subtle.importKey("jwk", publicJWK, importKeyParams, true, ["verify"]);
    return { alg, kid, privateKey, publicKey };
}

export function expiresTime(durationSeconds) {
    let now = Math.floor(Date.now() / 1e3);
    return {
        iat: now,
        exp: now + durationSeconds,
    };
}

export async function create(key, claims) {
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
