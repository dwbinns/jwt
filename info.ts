// JWT inspection: parsing and expiry helpers. No keys required.

import * as b64url from "@dwbinns/base/64url";
import type { JwtClaims, JwtHeader, ParsedJwt } from "./common.ts";

export type { JwtClaims, JwtHeader, ParsedJwt };

/** Synchronously parse a JWT without verification. */
export function parse(text: string): ParsedJwt {
    let [headerEncoded, claimsEncoded, signatureEncoded] = text.trim().split(".");
    if (!headerEncoded || !claimsEncoded || !signatureEncoded) {
        throw new Error("Invalid JWT format");
    }
    let header = JSON.parse(b64url.decodeText(headerEncoded)) as JwtHeader;
    let claims = JSON.parse(b64url.decodeText(claimsEncoded)) as JwtClaims;
    let signature = b64url.decode(signatureEncoded);
    let signed = `${headerEncoded}.${claimsEncoded}`;
    return { header, claims, signature, signed };
}

/** Returns iat/exp claims spanning the given duration from now. */
export function expiredTime(durationSeconds: number): { iat: number; exp: number } {
    let now = Math.floor(Date.now() / 1e3);
    return {
        iat: now,
        exp: now + durationSeconds,
    };
}

/** Fraction of the JWT's lifetime that has elapsed (0 when never expires). */
export function expiredFraction(jwt: string, createdAt?: Date, now = new Date()): number {
    const { claims } = parse(jwt);
    let { exp, iat } = claims;
    if (!exp) {
        return 0;
    }
    if (!iat && !createdAt) {
        throw new Error("No creation time or issued time available");
    }
    const created = createdAt ? createdAt.getTime() / 1e3 : iat!;
    const issuedAt = iat || createdAt!.getTime() / 1e3;
    return (now.getTime() / 1e3 - created) / (exp - issuedAt);
}
