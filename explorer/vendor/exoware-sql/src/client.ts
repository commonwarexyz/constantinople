import { create } from '@bufbuild/protobuf';
import { createClient, type CallOptions, type Client as ConnectClient } from '@connectrpc/connect';
import {
  createTransport,
  type ClientOptions as SdkClientOptions,
} from '@exowarexyz/sdk';
import {
  QueryRequestSchema as SqlQueryRequestSchema,
  type QueryResponse as SqlQueryResponse,
} from './generated/proto/sql/v1/query_pb.js';
import {
  IndexLayout as SqlIndexLayout,
  TablesRequestSchema as SqlTablesRequestSchema,
  type Column as SqlColumn,
  type Index as SqlIndex,
  type Table as SqlTable,
} from './generated/proto/sql/v1/schema_pb.js';
import { Service as SqlService } from './generated/proto/sql/v1/service_pb.js';
import {
  SubscribeRequestSchema as SqlSubscribeRequestSchema,
  type SubscribeResponse as SqlSubscribeResponse,
} from './generated/proto/sql/v1/stream_pb.js';
import {
  type Cell as SqlCell,
  type Row as SqlRow,
} from './generated/proto/sql/v1/common_pb.js';

export type SqlClientOptions = SdkClientOptions;

/**
 * Typed view of a single row cell.
 *
 * - `null` is SQL NULL (wire `null_value`).
 * - `bigint` covers Int64, UInt64 (unsigned), Date64, and Timestamp.
 * - `number` covers Float64 and Date32 (days since epoch).
 * - `Uint8Array` covers FixedSizeBinary and the big-endian encodings of
 *   Decimal128 (16 bytes) / Decimal256 (32 bytes).
 * - `CellValue[]` covers `List<...>` columns; elements use the same type.
 * - The `undefined` case means the server sent an unknown oneof variant.
 */
export type CellValue =
  | bigint
  | number
  | boolean
  | string
  | Uint8Array
  | CellValue[]
  | null
  | undefined;

export interface DecodedRow {
  /** Column → value. Columns are in the same order as the `columns` array. */
  values: Record<string, CellValue>;
  /** Parallel array of values for positional access. */
  cells: CellValue[];
}

export interface DecodedQueryResult {
  columns: string[];
  rows: DecodedRow[];
}

export interface DecodedSubscribeFrame {
  sequenceNumber: bigint;
  columns: string[];
  rows: DecodedRow[];
}

export interface DecodedColumn {
  name: string;
  /** Arrow DataType debug string, e.g. `Int64`, `Utf8`, `Decimal128(38, 10)`. */
  dataType: string;
  nullable: boolean;
}

export type DecodedIndexLayout = 'lexicographic' | 'zorder';

export interface DecodedIndex {
  name: string;
  layout: DecodedIndexLayout;
  /** Names of columns in key order. */
  keyColumns: string[];
  /** Names of columns included in the index payload ("covered"). */
  coverColumns: string[];
}

export interface DecodedTable {
  name: string;
  columns: DecodedColumn[];
  /** Names of primary-key columns in key-sort order. */
  primaryKeyColumns: string[];
  indexes: DecodedIndex[];
}

function cellToValue(cell: SqlCell): CellValue {
  switch (cell.kind.case) {
    case 'nullValue':
      return null;
    case 'int64Value':
    case 'uint64Value':
    case 'date64Value':
    case 'timestampValue':
      return cell.kind.value;
    case 'float64Value':
    case 'date32Value':
      return cell.kind.value;
    case 'booleanValue':
      return cell.kind.value;
    case 'utf8Value':
      return cell.kind.value;
    case 'fixedSizeBinaryValue':
    case 'decimal128Value':
    case 'decimal256Value':
      return cell.kind.value;
    case 'listValue':
      return cell.kind.value.elements.map(cellToValue);
    default:
      // Unknown oneof variant (forward-compatibility safeguard). Distinct
      // from SQL NULL (`null`).
      return undefined;
  }
}

function decodeRow(row: SqlRow, columns: string[]): DecodedRow {
  const cells = row.cells.map(cellToValue);
  const values: Record<string, CellValue> = {};
  columns.forEach((column, index) => {
    values[column] = cells[index] ?? null;
  });
  return { values, cells };
}

function decodeQuery(response: SqlQueryResponse): DecodedQueryResult {
  const columns = response.column;
  return {
    columns,
    rows: response.rows.map((row) => decodeRow(row, columns)),
  };
}

function decodeSubscribe(response: SqlSubscribeResponse): DecodedSubscribeFrame {
  const columns = response.column;
  return {
    sequenceNumber: response.sequenceNumber,
    columns,
    rows: response.rows.map((row) => decodeRow(row, columns)),
  };
}

function decodeLayout(layout: SqlIndexLayout): DecodedIndexLayout {
  return layout === SqlIndexLayout.Z_ORDER ? 'zorder' : 'lexicographic';
}

function decodeColumn(column: SqlColumn): DecodedColumn {
  return {
    name: column.name,
    dataType: column.dataType,
    nullable: column.nullable,
  };
}

function decodeIndex(index: SqlIndex, columnNames: string[]): DecodedIndex {
  const lookup = (idx: number) => columnNames[idx] ?? `#${idx}`;
  return {
    name: index.name,
    layout: decodeLayout(index.layout),
    keyColumns: index.keyColumns.map(lookup),
    coverColumns: index.coverColumns.map(lookup),
  };
}

function decodeTable(table: SqlTable): DecodedTable {
  const columns = table.columns.map(decodeColumn);
  const columnNames = columns.map((c) => c.name);
  const lookup = (idx: number) => columnNames[idx] ?? `#${idx}`;
  return {
    name: table.name,
    columns,
    primaryKeyColumns: table.primaryKeyColumns.map(lookup),
    indexes: table.indexes.map((index) => decodeIndex(index, columnNames)),
  };
}

/**
 * Thin wrapper around the `sql.v1.Service` Connect client.
 *
 * `subscribe` re-runs the server-side predicate on every ingest batch that
 * touches the named table and yields one frame per batch of matching rows.
 * `query` runs an arbitrary SQL statement against the server's session and
 * returns rows as typed cells.
 */
export class SqlClient {
  private readonly rpc: ConnectClient<typeof SqlService>;

  constructor(baseUrl: string, options: SqlClientOptions = {}) {
    const transport = createTransport(baseUrl, options);
    this.rpc = createClient(SqlService, transport);
  }

  async query(sql: string, options?: CallOptions): Promise<DecodedQueryResult> {
    const response = await this.rpc.query(
      create(SqlQueryRequestSchema, { sql }),
      options,
    );
    return decodeQuery(response);
  }

  async tables(options?: CallOptions): Promise<DecodedTable[]> {
    const response = await this.rpc.tables(
      create(SqlTablesRequestSchema, {}),
      options,
    );
    return response.tables.map(decodeTable);
  }

  async *subscribe(
    request: {
      table: string;
      whereSql?: string;
      sinceSequenceNumber?: bigint;
    },
    options?: CallOptions,
  ): AsyncIterable<DecodedSubscribeFrame> {
    const stream = this.rpc.subscribe(
      create(SqlSubscribeRequestSchema, {
        table: request.table,
        whereSql: request.whereSql ?? '',
        ...(request.sinceSequenceNumber !== undefined
          ? { sinceSequenceNumber: request.sinceSequenceNumber }
          : {}),
      }),
      options,
    );
    for await (const frame of stream) {
      yield decodeSubscribe(frame);
    }
  }
}
