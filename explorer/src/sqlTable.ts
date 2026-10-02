import type { Table } from '@exowarexyz/sql';

export interface SqlRow {
    readonly table: Table;
    readonly index: number;
}

export function firstTableRow(table: Table): SqlRow | undefined {
    return table.numRows === 0 ? undefined : { table, index: 0 };
}

export function tableRows(table: Table): SqlRow[] {
    return Array.from({ length: table.numRows }, (_, index) => ({ table, index }));
}

export function columnValue(row: SqlRow, column: string): unknown {
    return row.table.getChild(column)?.get(row.index);
}
