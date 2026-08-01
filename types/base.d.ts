declare module "@dwbinns/base/64" {
    export function encodeText(string: string): string;
    export function encode(bytes: Uint8Array): string;
    export function decode(string: string): Uint8Array;
    export function decodeText(string: string): string;
}

declare module "@dwbinns/base/64url" {
    export function encodeText(string: string): string;
    export function encode(bytes: Uint8Array): string;
    export function decode(string: string): Uint8Array;
    export function decodeText(string: string): string;
}
