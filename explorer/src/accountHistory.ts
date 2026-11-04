interface AccountHistoryScope {
    readonly indexerUrl: string;
    readonly simplexVerificationMaterial: string;
    readonly account: string;
}

interface AccountHistoryRequest {
    readonly key: string;
    readonly signal: AbortSignal;
}

interface AccountVersion {
    readonly txCount: bigint;
    readonly writeHeight: bigint;
    readonly location: bigint;
}

/** Each mounted account view owns its requests and observations for this session. */
export class AccountHistorySession {
    private active: AccountHistoryRequest | null = null;
    private readonly versions = new Map<string, AccountVersion>();

    begin(scope: AccountHistoryScope, signal: AbortSignal): AccountHistoryRequest {
        const request = { key: accountHistoryContextKey(scope), signal };
        this.active = request;
        return request;
    }

    invalidate(): void {
        this.active = null;
    }

    isCurrent(request: AccountHistoryRequest): boolean {
        return this.active === request && !request.signal.aborted;
    }

    /** Only the request that can publish may advance the rollback guard. */
    observe(request: AccountHistoryRequest, version: AccountVersion): boolean {
        if (!this.isCurrent(request)) return false;
        const previous = this.versions.get(request.key);
        if (previous) {
            if (version.location === previous.location && (
                version.txCount !== previous.txCount || version.writeHeight !== previous.writeHeight
            )) {
                throw new Error('account location has conflicting version metadata');
            }
            if (version.writeHeight >= previous.writeHeight && version.txCount < previous.txCount) {
                throw new Error(`account transaction count regressed from ${previous.txCount} to ${version.txCount}`);
            }
        }

        // Historical versions remain valid; they do not lower the newest writer observation.
        if (!previous || version.writeHeight >= previous.writeHeight) {
            this.versions.set(request.key, { ...version });
        }
        return true;
    }
}

export function accountHistoryContextKey(scope: AccountHistoryScope): string {
    return JSON.stringify([
        scope.indexerUrl.trim().replace(/\/+$/, ''),
        scope.simplexVerificationMaterial.trim().toLowerCase(),
        scope.account.trim().replace(/^0x/i, '').toLowerCase(),
    ]);
}
