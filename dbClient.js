const path = require('path');
const sqlite3 = require('sqlite3').verbose();
let Pool;
try {
  ({ Pool } = require('pg'));
} catch {
  Pool = null;
}

function createDb() {
  const url = process.env.DATABASE_URL;
  if (url && Pool) {
    const pool = new Pool({ connectionString: url });
    const convert = sql => {
      let i = 0;
      return sql.replace(/\?/g, () => '$' + ++i);
    };
    return {
      run(sql, params = [], cb = () => {}) {
        pool.query(convert(sql), params).then(() => cb()).catch(cb);
      },
      get(sql, params = [], cb = () => {}) {
        pool.query(convert(sql), params).then(r => cb(null, r.rows[0])).catch(cb);
      },
      all(sql, params = [], cb = () => {}) {
        pool.query(convert(sql), params).then(r => cb(null, r.rows)).catch(cb);
      },
      prepare(sql) {
        const text = convert(sql);
        return {
          run: (params = [], cb = () => {}) => {
            pool.query(text, params).then(() => cb()).catch(cb);
          },
          get: (params = [], cb = () => {}) => {
            pool.query(text, params).then(r => cb(null, r.rows[0])).catch(cb);
          },
          all: (params = [], cb = () => {}) => {
            pool.query(text, params).then(r => cb(null, r.rows)).catch(cb);
          }
        };
      },
      serialize(fn) {
        fn();
      }
    };
  }

  const dbFile = process.env.DB_FILE || path.join(__dirname, 'tasks.db');
  return new sqlite3.Database(dbFile);
}

module.exports = { createDb };
