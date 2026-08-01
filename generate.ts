// JWT generation: private key import and signing.

import * as b64 from "@dwbinns/base/64";
import * as b64url from "@dwbinns/base/64url";
import { getParameters, requireKid, type Algorithm, type JwtClaims } from "./common.ts";

export type { Algorithm, JwtClaims };

export interface PrivateKeyEntry {
    alg: Algorithm;
    kid?: string;
    privateKey: CryptoKey;
}

/**
 * Import a private key from a JWK. The JWK must contain the private component (`d`).
 * Accepts either (jwk) with embedded alg/kid, or (alg, kid, jwk).
 */
export async function importPrivateKey(jwk: JsonWebKey): Promise<PrivateKeyEntry>;
export async function importPrivateKey(alg: Algorithm, kid: string | undefined, jwk: JsonWebKey): Promise<PrivateKeyEntry>;
export async function importPrivateKey(
    algOrJwk: Algorithm | JsonWebKey,
    kid?: string,
    jwk?: JsonWebKey
): Promise<PrivateKeyEntry> {
    let alg: Algorithm;
    if (typeof algOrJwk === "string") {
        alg = algOrJwk;
    } else {
        jwk = algOrJwk;
        ({ alg, kid } = requireKid(jwk as JsonWebKey & { kid?: string; alg?: string }));
    }

    if (!jwk!.d) throw new Error("JWK does not contain a private key");

    let { importKeyParams } = getParameters(alg);

    let privateKey = await crypto.subtle.importKey("jwk", jwk!, importKeyParams, true, ["sign"]);
    return { alg, kid, privateKey };
}

/**
 * Import a private key from a PEM string (pkcs8, `BEGIN PRIVATE KEY`).
 * For `BEGIN RSA PRIVATE KEY` (pkcs1) convert first:
 *   openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in pkcs1.key -out pkcs8.key
 */
export async function importPemPrivateKey(alg: Algorithm, kid: string | undefined, pem: string): Promise<PrivateKeyEntry> {
    let lines = pem.split("\n").map(line => line.trim()).filter(Boolean);
    let title = (lines[0] ?? "").replaceAll("-", "").trim();

    if (title != "BEGIN PRIVATE KEY") throw new Error("PEM does not contain a private key");

    let { importKeyParams } = getParameters(alg);

    let privateKey = await crypto.subtle.importKey(
        "pkcs8",
        b64.decode(lines.filter(line => !line.startsWith("--")).join("")) as BufferSource,
        importKeyParams,
        true,
        ["sign"]
    );

    return { alg, kid, privateKey };
}

/** Create (sign) a JWT with a single private key. */
export async function create(key: PrivateKeyEntry, claims: JwtClaims): Promise<string> {
    let { alg, kid, privateKey } = key;
    let { signatureParams } = getParameters(alg);

    let header = { kid, alg };
    let headerEncoded = b64url.encodeText(JSON.stringify(header));
    let claimsEncoded = b64url.encodeText(JSON.stringify(claims));

    let signatureEncoded = b64url.encode(new Uint8Array(await crypto.subtle.sign(
        signatureParams,
        privateKey,
        new TextEncoder().encode(`${headerEncoded}.${claimsEncoded}`)
    )));
    return `${headerEncoded}.${claimsEncoded}.${signatureEncoded}`;
}
