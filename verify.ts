// JWT verification: public key import and signature/expiry checks.

import * as b64 from "@dwbinns/base/64";
import { getParameters, type Algorithm, type JwtClaims } from "./common.ts";
import { parse } from "./info.ts";

export type { Algorithm, JwtClaims };

export interface PublicKeyEntry {
    alg: Algorithm;
    kid?: string;
    publicKey: CryptoKey;
}

/** Import a public key from a JWK. Any private component is stripped before import. */
export async function importPublicKey(alg: Algorithm, kid: string | undefined, jwk: JsonWebKey): Promise<PublicKeyEntry> {
    let { importKeyParams } = getParameters(alg);
    let publicJWK = { ...jwk, d: undefined, dp: undefined, dq: undefined, q: undefined, qi: undefined, key_ops: undefined };
    let publicKey = await crypto.subtle.importKey("jwk", publicJWK, importKeyParams, true, ["verify"]);
    return { alg, kid, publicKey };
}

/** Import a public key from a PEM string (spki, `BEGIN PUBLIC KEY`). */
export async function importPemPublicKey(alg: Algorithm, kid: string | undefined, pem: string): Promise<PublicKeyEntry> {
    let lines = pem.split("\n").map(line => line.trim()).filter(Boolean);
    let title = (lines[0] ?? "").replaceAll("-", "").trim();

    if (title != "BEGIN PUBLIC KEY") throw new Error("PEM does not contain a public key");

    let { importKeyParams } = getParameters(alg);

    let publicKey = await crypto.subtle.importKey(
        "spki",
        b64.decode(lines.filter(line => !line.startsWith("--")).join("")) as BufferSource,
        importKeyParams,
        true,
        ["verify"]
    );

    return { alg, kid, publicKey };
}

interface Jwks {
    keys: ({ alg?: Algorithm; kid?: string } & JsonWebKey)[];
}

/** Import all usable public keys from a JWKS object. Keys without an `alg` are skipped. */
export async function importJWKS({ keys }: Jwks): Promise<PublicKeyEntry[]> {
    let imported = await Promise.all(keys.map(async ({ alg, kid, ...jwk }): Promise<PublicKeyEntry | null> => {
        if (!alg) return null;
        return await importPublicKey(alg, kid, jwk);
    }));
    return imported.filter((key): key is PublicKeyEntry => key !== null);
}

export async function importURLJWKS(url: URL): Promise<PublicKeyEntry[]> {
    let response = await fetch(url)
    if (!response.ok) throw new Error("JWKS fetch failed");

    return await importJWKS(await response.json());
}

export async function importHostJWKS(hostname: string): Promise<PublicKeyEntry[]> {
    return await importURLJWKS(new URL(`https://${hostname}./well-known/jwks.json`));
}

/** Parse and verify a JWT against one or more public keys, returning its claims. */
export async function verify(keys: PublicKeyEntry | PublicKeyEntry[], text: string, now = new Date()): Promise<JwtClaims> {
    let { header, claims, signature, signed } = parse(text);

    let keyList = Array.isArray(keys) ? keys : [keys];

    for (let key of keyList) {

        let { alg, kid, publicKey } = key;

        let { signatureParams } = getParameters(alg);

        if (header.kid != kid || header.alg != alg) {
            continue;
        }

        let valid = await crypto.subtle.verify(
            signatureParams,
            publicKey,
            signature as BufferSource,
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
