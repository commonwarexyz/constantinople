const ED25519_PUBLIC_KEY_HEX_LENGTH = 64;

export interface ParsedValidatorEndpoint {
    readonly normalized: string;
    readonly ipVersion: 4 | 6;
    readonly addressBytes: Uint8Array;
    readonly port: number;
}

/** Normalize a 32-byte Ed25519 public key to unprefixed lowercase hex. */
export function normalizeEd25519PublicKey(value: string): string {
    const normalized = value
        .trim()
        .replace(/^ed25519:/i, '')
        .replace(/^0x/i, '')
        .toLowerCase();
    if (!new RegExp(`^[0-9a-f]{${ED25519_PUBLIC_KEY_HEX_LENGTH}}$`).test(normalized)) {
        throw new Error('public key must be a 32-byte Ed25519 key');
    }
    return normalized;
}

/** Normalize an IPv4:port or [IPv6]:port validator endpoint. */
export function normalizeValidatorEndpoint(value: string): string {
    return parseValidatorEndpoint(value).normalized;
}

/** Parse a validator endpoint into the fields used by commonware's SocketAddr codec. */
export function parseValidatorEndpoint(value: string): ParsedValidatorEndpoint {
    const input = value.trim();
    const ipv6Match = /^\[([^\]]+)\]:(\d+)$/.exec(input);
    if (ipv6Match) {
        const addressBytes = parseIpv6(ipv6Match[1]);
        const port = parsePort(ipv6Match[2]);
        return {
            normalized: `[${formatIpv6(addressBytes)}]:${port}`,
            ipVersion: 6,
            addressBytes,
            port,
        };
    }

    const ipv4Match = /^([^:]+):(\d+)$/.exec(input);
    if (ipv4Match) {
        const addressBytes = parseIpv4(ipv4Match[1]);
        const port = parsePort(ipv4Match[2]);
        return {
            normalized: `${[...addressBytes].join('.')}:${port}`,
            ipVersion: 4,
            addressBytes,
            port,
        };
    }

    throw new Error('address must be IPv4:port or [IPv6]:port');
}

function parsePort(value: string): number {
    const port = Number(value);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
        throw new Error('port must be between 1 and 65535');
    }
    return port;
}

function parseIpv4(value: string): Uint8Array {
    const parts = value.split('.');
    if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) {
        throw new Error('address must contain a valid IPv4 address');
    }
    const octets = parts.map(Number);
    if (octets.some((octet) => octet > 255)) {
        throw new Error('address must contain a valid IPv4 address');
    }
    return Uint8Array.from(octets);
}

function parseIpv6(value: string): Uint8Array {
    if (value.length === 0 || value.includes('%') || value.split('::').length > 2) {
        throw new Error('address must contain a valid IPv6 address');
    }

    let canonicalInput = value;
    if (value.includes('.')) {
        const suffixStart = value.lastIndexOf(':');
        if (suffixStart < 0) {
            throw new Error('address must contain a valid IPv6 address');
        }
        const ipv4 = parseIpv4(value.slice(suffixStart + 1));
        const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
        const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
        canonicalInput = `${value.slice(0, suffixStart + 1)}${high}:${low}`;
    }

    const [leftText, rightText, ...extra] = canonicalInput.split('::');
    if (extra.length !== 0) {
        throw new Error('address must contain a valid IPv6 address');
    }
    const hasCompression = canonicalInput.includes('::');
    const left = parseIpv6Side(leftText);
    const right = hasCompression ? parseIpv6Side(rightText ?? '') : [];
    const missing = 8 - left.length - right.length;
    if ((!hasCompression && missing !== 0) || (hasCompression && missing < 1)) {
        throw new Error('address must contain a valid IPv6 address');
    }
    const groups = [...left, ...Array.from({ length: missing }, () => 0), ...right];
    if (groups.length !== 8) {
        throw new Error('address must contain a valid IPv6 address');
    }

    const bytes = new Uint8Array(16);
    groups.forEach((group, index) => {
        bytes[index * 2] = group >>> 8;
        bytes[index * 2 + 1] = group & 0xff;
    });
    return bytes;
}

function parseIpv6Side(value: string): number[] {
    if (value === '') return [];
    const groups = value.split(':');
    if (groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) {
        throw new Error('address must contain a valid IPv6 address');
    }
    return groups.map((group) => Number.parseInt(group, 16));
}

function formatIpv6(bytes: Uint8Array): string {
    const groups = Array.from({ length: 8 }, (_, index) =>
        ((bytes[index * 2] << 8) | bytes[index * 2 + 1]).toString(16),
    );
    let bestStart = -1;
    let bestLength = 0;
    for (let start = 0; start < groups.length;) {
        if (groups[start] !== '0') {
            start += 1;
            continue;
        }
        let end = start + 1;
        while (end < groups.length && groups[end] === '0') end += 1;
        if (end - start > bestLength) {
            bestStart = start;
            bestLength = end - start;
        }
        start = end;
    }
    if (bestLength < 2) return groups.join(':');
    const left = groups.slice(0, bestStart).join(':');
    const right = groups.slice(bestStart + bestLength).join(':');
    return `${left}::${right}`;
}
