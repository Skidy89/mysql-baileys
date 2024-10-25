import * as sqlite3 from 'sqlite3';
import { Database, open } from "sqlite";
import { performance } from 'perf_hooks';
import { Logger } from "pino";
import { AuthenticationState, BufferJSON, initAuthCreds, proto } from '@skidy89/baileys';




let dbInstance: Database | null = null;

const getDatabaseConnection = async (filename: string, customLogger: Logger): Promise<Database> => {
    if (dbInstance) return dbInstance;

    dbInstance = await open({
        filename: filename,
        driver: sqlite3.Database
    });

    await dbInstance.exec(`
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA temp_store = MEMORY;
        PRAGMA mmap_size = 268435456;
        PRAGMA cache_size = -64000;
        CREATE TABLE IF NOT EXISTS auth_state (
            session_id TEXT,
            data_key TEXT,
            data_value TEXT,
            PRIMARY KEY (session_id, data_key)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_session_key ON auth_state (session_id, data_key);
    `);

    customLogger.debug('Database connection established and configured');
    return dbInstance;
};


const profile = async (name: string, fn: () => Promise<any>, logger: Logger) => {
    const start = performance.now();
    const result = await fn();
    const end = performance.now();
    logger.debug(`${name} took ${(end - start).toFixed(2)} ms`);
    return result;
};

async function useSQLiteAuthState(sessionId: string, filename: string, customLogger: Logger): Promise<{
    state: AuthenticationState,
    saveCreds: () => Promise<void>,
    deleteSession: () => Promise<void>
}> {
    const logger = customLogger;
    const db = await getDatabaseConnection(filename, customLogger);

    const writeData = async (key: string, data: any) => {
        const serialized = JSON.stringify(data, BufferJSON.replacer);
        await db.run('INSERT OR REPLACE INTO auth_state (session_id, data_key, data_value) VALUES (?, ?, ?)', [sessionId, key, serialized]);
    };

    const readData = async (key: string): Promise<any | null> => {
        const row = await db.get('SELECT data_value FROM auth_state WHERE session_id = ? AND data_key = ?', [sessionId, key]);
        return row?.data_value ? typeof row.data_value === 'object' ? JSON.parse(row.data_value, BufferJSON.reviver) : row.data_value : null;
    };

    const creds = await profile('readCreds', () => readData('auth_creds'), logger) || initAuthCreds();

    const state: AuthenticationState = {
        creds,
        keys: {
            get: async (type, ids) => {
                return profile('keys.get', async () => {
                    const data: { [id: string]: any } = {};
                    const placeholders = ids.map(() => '?').join(',');
                    const query = `SELECT data_key, data_value FROM auth_state WHERE session_id = ? AND data_key IN (${placeholders})`;
                    const params = [sessionId, ...ids.map(id => `${type}-${id}`)];
                    const rows = await db.all(query, params);
                    rows.forEach(row => {
                        const id = row.data_key.split('-')[1];
                        let value = JSON.parse(row.data_value, BufferJSON.reviver)
                        if (type === 'app-state-sync-key') {
                            value = proto.Message.AppStateSyncKeyData.fromObject(value);
                        }
                        data[id] = value;
                    });
                    return data;
                }, logger);
            },
            set: async (data) => {
                return profile('keys.set', async () => {
                    await db.run('BEGIN TRANSACTION');

                    const instert: any[] = [];
                    const deleteKeys: string[] = [];
                for (const [category, categoryData] of Object.entries(data)) {
                    for (const [id, value] of Object.entries(categoryData || {})) {
                        const key = `${category}-${id}`;
                        if (value) {
                           const serialized = JSON.stringify(value, BufferJSON.replacer)
                           instert.push(sessionId, key, serialized);
                        } else {
                            deleteKeys.push(key);
                        }
                }
                }

                    if (instert.length) {
                        const placeholders = new Array(instert.length / 3).fill('(?, ?, ?)').join(',');
                        await db.run(`INSERT OR REPLACE INTO auth_state (session_id, data_key, data_value) VALUES ${placeholders}`, instert);
                    }

                    if (deleteKeys.length) {
                        const placeholders = deleteKeys.map(() => '?').join(',');
                        await db.run(`DELETE FROM auth_state WHERE session_id = ? AND data_key IN (${placeholders})`, [sessionId, ...deleteKeys]);
                    }

                    await db.run('COMMIT');
                }, logger);
            },
        },
    };

    return {
        state,
        saveCreds: async () => {
            await profile('saveCreds', () => writeData('auth_creds', state.creds), logger);
        },
        deleteSession: async () => {
            await profile('deleteSession', () => db.run('DELETE FROM auth_state WHERE session_id = ?', sessionId), logger);
        },
    };
}

export {useSQLiteAuthState}