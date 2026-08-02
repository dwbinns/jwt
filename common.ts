// Shared internals for the @dwbinns/jwt submodules (generate, verify, info).

export type Algorithm = "RS256" | "ES256" | "EdDSA";

export interface JwtHeader {
    alg?: string;
    kid?: string;
    [key: string]: unknown;
}

export interface JwtClaims {
    exp?: number;
    iat?: number;
    [key: string]: unknown;
}

export interface ParsedJwt {
    header: JwtHeader;
    claims: JwtClaims;
    signature: Uint8Array;
    signed: string;
}

export interface AlgorithmParameters {
    importKeyParams: RsaHashedImportParams | EcKeyImportParams | AlgorithmIdentifier;
    signatureParams: AlgorithmIdentifier | EcdsaParams;
}

export const algorithms: Record<Algorithm, AlgorithmParameters> = {
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
    },
    "EdDSA": {
        importKeyParams: {
            name: "Ed25519"
        },
        signatureParams: {
            name: "Ed25519"
        }
     }
}

export function getParameters(alg: Algorithm): AlgorithmParameters {
    let parameters = algorithms[alg];
    if (!parameters) {
        throw new Error("Unknown algorithm: " + alg);
    }
    return parameters;
}

export function requireKid(jwk: JsonWebKey & { kid?: string; alg?: string }): { alg: Algorithm; kid: string } {
    if (!jwk.alg) throw new Error("JWK missing 'alg'");
    if (!jwk.kid) throw new Error("JWK missing 'kid'");
    return { alg: jwk.alg as Algorithm, kid: jwk.kid };
}
