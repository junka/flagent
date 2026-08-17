// RCE 工具集 smoke 测试：验证 8 个 RCE 排查工具均注册并能产出合理 payload/清单。
"use strict";

const { createToolRegistry } = require("../dist/tools/factory");

let pass = 0,
  fail = 0;
const assert = (cond, msg) => {
  if (cond) {
    pass++;
    console.log("  ✓ " + msg);
  } else {
    fail++;
    console.log("  ✗ " + msg);
  }
};

async function main() {
  const reg = createToolRegistry();
  const all = reg.getAll();
  console.log("\n== RCE 工具集 smoke 测试 ==");

  // 1. 全部 8 个工具已注册
  const expected = [
    "cmd_injection_payloads",
    "ssti_detect",
    "deser_payload_gen",
    "nonalpha_webshell",
    "lfi_to_rce",
    "blind_rce_exfil",
    "post_rce_enum",
    "upload_bypass_checklist",
  ];
  for (const name of expected) {
    assert(reg.get(name) !== undefined, `工具 ${name} 已注册`);
  }
  assert(reg.get("cmd_injection_payloads").category === "web", "RCE 工具 category=web");
  assert(
    reg.get("cmd_injection_payloads").concurrent === true,
    "RCE 工具 concurrent=true（只读生成，可并发）"
  );

  // 2. 命令注入 payload：含分隔符 + 绕过
  console.log("\n-- cmd_injection_payloads --");
  {
    const out = await reg.execute("cmd_injection_payloads", {
      inject_point: "ping cmd 参数",
      filtered: "空格;|`$",
      blind: true,
    });
    assert(out.includes("分隔符"), "含分隔符段落");
    assert(out.includes("空格绕过"), "含空格绕过段落");
    assert(out.includes("关键字绕过"), "含关键字绕过段落");
    assert(out.includes("盲注外带"), "blind=true 时含外带段落");
    assert(out.includes("${IFS}"), "含 ${IFS} 空格绕过");
    assert(out.includes("base64"), "含 base64 关键字绕过");
    assert(out.includes("dnslog") || out.includes("ceye"), "含 DNS 外带");
  }

  // 3. SSTI 识别：jinja2 (7*'7' => 7777777)
  console.log("\n-- ssti_detect (jinja2) --");
  {
    const out = await reg.execute("ssti_detect", {
      probe_results: "{{7*7}} => 49\n{{7*'7'}} => 7777777",
    });
    assert(out.includes("Jinja2"), "识别为 Jinja2");
    assert(out.includes("lipsum") || out.includes("popen"), "给出 Jinja2 RCE payload");
  }

  // 4. SSTI 识别：twig (7*'7' => 49)
  console.log("\n-- ssti_detect (twig) --");
  {
    const out = await reg.execute("ssti_detect", {
      probe_results: "{{7*7}} => 49\n{{7*'7'}} => 49",
    });
    assert(out.includes("Twig"), "识别为 Twig");
    assert(out.includes("_self.env"), "给出 Twig RCE payload");
  }

  // 5. SSTI 识别：java freemarker
  console.log("\n-- ssti_detect (freemarker) --");
  {
    const out = await reg.execute("ssti_detect", {
      probe_results: "${7*7} => 49",
    });
    assert(out.includes("FreeMarker") || out.includes("Velocity"), "识别为 FreeMarker/Velocity");
    assert(out.includes("freemarker.template.utility.Execute"), "给出 FreeMarker payload");
  }

  // 6. 反序列化：java
  console.log("\n-- deser_payload_gen (java) --");
  {
    const out = await reg.execute("deser_payload_gen", {
      lang: "java",
      context: "Shiro rememberMe",
    });
    assert(out.includes("ysoserial"), "提及 ysoserial");
    assert(out.includes("CommonsCollections"), "提及 CommonsCollections 链");
    assert(out.includes("Shiro550"), "提及 Shiro550");
  }

  // 7. 反序列化：python
  console.log("\n-- deser_payload_gen (python) --");
  {
    const out = await reg.execute("deser_payload_gen", { lang: "python" });
    assert(out.includes("__reduce__"), "提及 __reduce__");
    assert(out.includes("pickle.dumps"), "提及 pickle.dumps");
  }

  // 8. 无字母数字 webshell
  console.log("\n-- nonalpha_webshell --");
  {
    const out = await reg.execute("nonalpha_webshell", { technique: "auto" });
    assert(out.includes("异或"), "含异或构造");
    assert(out.includes("自增"), "含自增构造");
    assert(out.includes("取反"), "含取反构造");
    assert(out.includes("$_GET[1]"), "含短 payload");
  }

  // 9. LFI → RCE
  console.log("\n-- lfi_to_rce --");
  {
    const out = await reg.execute("lfi_to_rce", {
      target: "http://t/?file=[FILE]",
      php: true,
    });
    assert(out.includes("access.log"), "含日志包含路径");
    assert(out.includes("pearcmd"), "含 pearcmd 路径");
    assert(out.includes("php://filter"), "含 php filter 读源码");
    assert(out.includes("pearcmd"), "含 pearcmd 路径");
    assert(out.includes("php://filter"), "含 php filter 读源码");
    assert(out.includes("优先级"), "含优先级建议");
  }

  // 10. 盲 RCE 外带
  console.log("\n-- blind_rce_exfil --");
  {
    const out = await reg.execute("blind_rce_exfil", {
      callback_domain: "abc.ceye.io",
      cmd: "cat /flag",
    });
    assert(out.includes("DNS 外带"), "含 DNS 外带");
    assert(out.includes("HTTP 外带"), "含 HTTP 外带");
    assert(out.includes("延时"), "含延时盲注");
    assert(out.includes("ceye.io"), "payload 含回连域名");
  }

  // 11. RCE 后枚举
  console.log("\n-- post_rce_enum --");
  {
    const out = await reg.execute("post_rce_enum", { goal: "both" });
    assert(out.includes("whoami"), "含基础信息");
    assert(out.includes("find / -name"), "含找 flag 命令");
    assert(out.includes("sudo -l"), "含提权排查");
    assert(out.includes("perm -4000"), "含 SUID 排查");
  }

  // 12. 上传绕过
  console.log("\n-- upload_bypass_checklist --");
  {
    const out = await reg.execute("upload_bypass_checklist", {
      restriction: "黑名单 php",
    });
    assert(out.includes("phtml"), "含可解析后缀");
    assert(out.includes("htaccess"), "含 .htaccess 绕过");
    assert(out.includes("GIF89a"), "含文件头绕过");
  }

  // 13. 总工具数
  assert(all.length >= 170, `总工具数 >= 170（实际 ${all.length}）`);

  console.log(`\n=== 结果: ${pass} passed, ${fail} failed ===`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error("测试异常:", e);
  process.exit(1);
});
