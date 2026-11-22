require('dotenv').config();

const fs = require('node:fs');
const path = require('node:path');
const initializeSqlJs = require('sql.js');

const databaseFile = path.resolve(process.env.DATABASE_FILE || './data/tasks.sqlite');
fs.mkdirSync(path.dirname(databaseFile), { recursive: true });

const schema = `
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS project_members (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (project_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    creator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assignee_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed')),
    priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high')),
    due_date TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    uploader_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    storage_name TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS project_invitations (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    email TEXT NOT NULL COLLATE NOCASE,
    token_hash TEXT NOT NULL UNIQUE,
    inviter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    accepted_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
    task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
    actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    read_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_members_user ON project_members(user_id, project_id);
  CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project_id);
  CREATE INDEX IF NOT EXISTS idx_tasks_assignee ON tasks(assignee_id);
  CREATE INDEX IF NOT EXISTS idx_comments_task ON comments(task_id);
  CREATE INDEX IF NOT EXISTS idx_attachments_task ON attachments(task_id);
  CREATE INDEX IF NOT EXISTS idx_invitations_project ON project_invitations(project_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, read_at, created_at);
`;

let database;
let persistDepth = 0;
let initialized;

function persist() {
  if (persistDepth || !database) return;
  const temporaryFile = `${databaseFile}.tmp`;
  fs.writeFileSync(temporaryFile, Buffer.from(database.export()));
  fs.renameSync(temporaryFile, databaseFile);
}

function translateError(error) {
  if (/UNIQUE constraint failed/.test(error.message)) error.code = 'SQLITE_CONSTRAINT_UNIQUE';
  return error;
}

function prepare(sql) {
  return {
    run(...parameters) {
      try {
        database.run(sql, parameters);
        const changes = database.getRowsModified();
        persist();
        return { changes };
      } catch (error) {
        throw translateError(error);
      }
    },
    get(...parameters) {
      try {
        const statement = database.prepare(sql);
        statement.bind(parameters);
        const row = statement.step() ? statement.getAsObject() : undefined;
        statement.free();
        return row;
      } catch (error) {
        throw translateError(error);
      }
    },
    all(...parameters) {
      try {
        const statement = database.prepare(sql);
        statement.bind(parameters);
        const rows = [];
        while (statement.step()) rows.push(statement.getAsObject());
        statement.free();
        return rows;
      } catch (error) {
        throw translateError(error);
      }
    },
  };
}

const db = {
  async initialize() {
    if (!initialized) {
      initialized = (async () => {
        const SQL = await initializeSqlJs({
          locateFile: (filename) => require.resolve(`sql.js/dist/${filename}`),
        });
        const contents = fs.existsSync(databaseFile) ? fs.readFileSync(databaseFile) : undefined;
        database = contents ? new SQL.Database(new Uint8Array(contents)) : new SQL.Database();
        database.run('PRAGMA foreign_keys = ON');
        database.exec(schema);
        persist();
      })();
    }
    return initialized;
  },
  exec(sql) {
    database.exec(sql);
    persist();
  },
  pragma(sql) {
    database.run(`PRAGMA ${sql}`);
  },
  prepare,
  transaction(callback) {
    return (...args) => {
      database.run('BEGIN');
      persistDepth += 1;
      try {
        const result = callback(...args);
        database.run('COMMIT');
        return result;
      } catch (error) {
        database.run('ROLLBACK');
        throw error;
      } finally {
        persistDepth -= 1;
        persist();
      }
    };
  },
  close() {
    if (!database) return;
    persist();
    database.close();
    database = undefined;
    initialized = undefined;
  },
};

module.exports = db;
