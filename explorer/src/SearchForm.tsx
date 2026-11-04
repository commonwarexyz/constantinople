import { type Ref, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { errorMessage } from './proofRetry';
import { normalizeSearchQuery, searchIndexer } from './search';

export interface SearchHandle {
    cancel: () => void;
}

interface Props {
    ref?: Ref<SearchHandle>;
    endpoint: string;
    onOpenAccount: (account: string) => void;
    onOpenTransaction: (digest: string) => void;
}

export function SearchForm({ ref, endpoint, onOpenAccount, onOpenTransaction }: Props) {
    const [query, setQuery] = useState('');
    const [message, setMessage] = useState('');
    const [loading, setLoading] = useState(false);
    const active = useRef<AbortController | null>(null);

    useEffect(() => () => active.current?.abort(), []);

    const cancel = () => {
        active.current?.abort();
        active.current = null;
        setLoading(false);
        setMessage('');
    };

    useImperativeHandle(ref, () => ({ cancel }));

    const search = async () => {
        active.current?.abort();
        const controller = new AbortController();
        active.current = controller;
        setMessage('');
        setLoading(true);
        try {
            const normalized = normalizeSearchQuery(query);
            const match = await searchIndexer(endpoint, normalized, controller.signal);
            if (controller.signal.aborted) return;
            if (match.kind === 'account') onOpenAccount(match.value);
            else onOpenTransaction(match.value);
        } catch (error) {
            if (!controller.signal.aborted) setMessage(errorMessage(error));
        } finally {
            if (active.current === controller) {
                active.current = null;
                setLoading(false);
            }
        }
    };

    return (
        <form className="search" role="search" aria-label="explorer search" aria-busy={loading}
            onSubmit={(event) => { event.preventDefault(); void search(); }}>
            <label className="visually-hidden" htmlFor="explorer-search">address or transaction hash</label>
            <div className="search__input">
                <input id="explorer-search" value={query} spellCheck={false} autoComplete="off"
                    placeholder="address or transaction hash" aria-describedby="explorer-search-status"
                    onChange={(event) => { cancel(); setQuery(event.target.value); }}
                    onKeyDown={(event) => { if (event.key === 'Escape') cancel(); }} />
                <button className="search__submit" type="submit" disabled={loading || !query.trim()}>search</button>
            </div>
            <p className="search__status" id="explorer-search-status" role="status">{loading ? 'searching' : message}</p>
        </form>
    );
}
