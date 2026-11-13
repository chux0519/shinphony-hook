// Relay database adapter over a Durable Object's SQLite (ctx.storage.sql).
// Same surface as nodeDatabase() in server/relay.mjs.
export function durableDatabase(storage) {
  const sql = storage.sql;
  const statement = query => ({
    get: (...args) => sql.exec(query, ...args).toArray()[0],
    all: (...args) => sql.exec(query, ...args).toArray(),
    run: (...args) => {
      const cursor = sql.exec(query, ...args);
      cursor.toArray();
      return { changes: cursor.rowsWritten };
    },
  });
  return {
    // Multi-statement schema text: run one statement at a time.
    exec: text => {
      for (const part of text.split(';').map(s => s.trim()).filter(Boolean)) sql.exec(part);
    },
    prepare: statement,
    columns: table => sql.exec(`PRAGMA table_info(${table})`).toArray().map(row => row.name),
    // Synchronous and atomic; throwing rolls back (BEGIN/COMMIT are not allowed).
    transaction: fn => storage.transactionSync(fn),
    close: () => {},
  };
}
