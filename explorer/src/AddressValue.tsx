// The explorer's account-address button: one home for the markup contract
// (aria-label, title, copyable classes) shared by the dashboard, account
// pages, and the paid-stream view.

export function AddressValue({
    disabled = false,
    plain = false,
    value,
    display,
    onOpenAddress,
}: {
    disabled?: boolean;
    plain?: boolean;
    value: string;
    /// Text to render instead of the full value (e.g. an abbreviation);
    /// the aria-label always carries the full value.
    display?: string;
    onOpenAddress: (value: string) => void;
}) {
    const className = [
        'copyable',
        'copyable--address',
        plain ? 'copyable--plain' : '',
    ]
        .filter(Boolean)
        .join(' ');

    return (
        <button
            aria-label={`open address ${value}`}
            className={className}
            disabled={disabled}
            onClick={() => onOpenAddress(value)}
            title="open address"
            type="button"
        >
            <span className="copyable__value">{display ?? value}</span>
        </button>
    );
}
