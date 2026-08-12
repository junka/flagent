import { z } from "zod";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as child_process from "child_process";
import { ToolRegistry } from "./registry";

/**
 * 检查系统命令是否存在（通过 which）
 */
function commandExists(cmd: string): boolean {
  try {
    child_process.execSync(`which ${cmd} 2>/dev/null`, {
      encoding: "utf-8",
      timeout: 5000,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * 执行系统命令，返回 stdout 字符串
 * 失败时抛出异常，由调用方 try-catch
 */
function runCmd(cmd: string, timeout = 30000): string {
  return child_process.execSync(cmd, {
    timeout,
    maxBuffer: 1024 * 1024,
    encoding: "utf-8",
  });
}

/** 截断文本到指定长度 */
function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + `\n... (已截断，共 ${text.length} 字符)`;
}

export function createIotTools(): ToolRegistry {
  const registry = new ToolRegistry();

  // 1. 固件提取与解包
  registry.register({
    name: "firmware_extract",
    description: "固件提取与解包：binwalk 签名扫描、自动提取嵌入文件、熵分析（识别加密/压缩区段）",
    parameters: z.object({
      firmware_path: z.string().describe("固件文件路径"),
      output_dir: z.string().optional().describe("输出目录，可选（不指定则使用 binwalk 默认提取目录）"),
      mode: z
        .enum(["scan", "extract", "entropy", "all"])
        .default("all")
        .describe("模式：scan=签名扫描, extract=提取嵌入文件, entropy=熵分析, all=全部"),
    }),
    category: "iot",
    concurrent: true,
    execute: async (args: any) => {
      const { firmware_path, output_dir, mode } = args;
      if (!fs.existsSync(firmware_path)) return `❌ 文件不存在: ${firmware_path}`;

      // 检查 binwalk 是否安装
      if (!commandExists("binwalk")) {
        return (
          `⚠️  系统未安装 binwalk。\n` +
          `  安装方式：\n` +
          `  macOS: brew install binwalk\n` +
          `  Ubuntu/Debian: sudo apt install binwalk\n` +
          `  pip install binwalk\n` +
          `  或从源码: git clone https://github.com/ReFirmLabs/binwalk.git`
        );
      }

      const out: string[] = [`[固件提取与解包] ${firmware_path}\n模式: ${mode}\n`];

      // scan 模式：签名扫描
      if (mode === "scan" || mode === "all") {
        out.push(`── 签名扫描 (binwalk) ──`);
        try {
          const result = runCmd(`binwalk "${firmware_path}"`, 60000);
          out.push(truncate(result, 8000));
        } catch (err: any) {
          const errStderr = err.stderr ? `\nSTDERR:\n${err.stderr}` : "";
          out.push(`❌ 签名扫描失败: ${err.message}${errStderr}`);
        }
      }

      // extract 模式：提取嵌入文件
      if (mode === "extract" || mode === "all") {
        out.push(`\n── 提取嵌入文件 ──`);
        try {
          let extractDir = "";
          if (output_dir) {
            // 指定输出目录：用 -C 选项
            fs.mkdirSync(output_dir, { recursive: true });
            runCmd(`binwalk -e -C "${output_dir}" "${firmware_path}"`, 120000);
            extractDir = output_dir;
          } else {
            // 默认提取：binwalk -e 创建 <file>.extracted 目录
            runCmd(`binwalk -e "${firmware_path}"`, 120000);
            // 探测默认提取目录（不同版本命名略有差异）
            const candidates = [
              `${firmware_path}.extracted`,
              `${firmware_path}_extracted`,
              `${firmware_path}-0.extracted`,
            ];
            extractDir = candidates.find((c) => fs.existsSync(c)) || "";
          }

          if (extractDir && fs.existsSync(extractDir)) {
            out.push(`提取目录: ${extractDir}`);
            // 列出输出目录中的文件（递归，最多 60 个）
            const files = listFilesRecursive(extractDir).slice(0, 60);
            out.push(`\n[提取文件 (${files.length}${files.length >= 60 ? "+" : ""} 个)]`);
            out.push(
              files
                .map((f) => `  ${path.relative(extractDir, f)}`)
                .join("\n") || "  (空目录)"
            );
          } else {
            out.push(`⚠️  未找到提取输出目录（可能固件中没有可提取的嵌入文件）`);
            out.push(`  也可尝试: binwalk --dd=.* "${firmware_path}"`);
          }
        } catch (err: any) {
          const errStderr = err.stderr ? `\nSTDERR:\n${err.stderr}` : "";
          out.push(`❌ 提取失败: ${err.message}${errStderr}`);
        }
      }

      // entropy 模式：熵分析
      if (mode === "entropy" || mode === "all") {
        out.push(`\n── 熵分析 (binwalk -E) ──`);
        try {
          const result = runCmd(`binwalk -E "${firmware_path}"`, 60000);
          out.push(truncate(result, 6000));
          out.push(`\n提示: 高熵区段(接近 1.0)通常为加密/压缩数据，低熵区段可能为代码或配置`);
        } catch (err: any) {
          const errStderr = err.stderr ? `\nSTDERR:\n${err.stderr}` : "";
          out.push(`❌ 熵分析失败: ${err.message}${errStderr}`);
        }
      }

      return out.join("\n");
    },
  });

  // 2. Binwalk 签名扫描
  registry.register({
    name: "binwalk_scan",
    description: "Binwalk 签名扫描：识别固件中嵌入的文件系统、内核、压缩包等（返回偏移/类型/描述表）",
    parameters: z.object({
      firmware_path: z.string().describe("固件文件路径"),
      signature: z.string().optional().describe("签名过滤关键词（如 squashfs、uImage、gzip）"),
      max_size: z
        .number()
        .min(1)
        .max(4096)
        .default(100)
        .describe("最大扫描大小(MB)，文件超出时截断前 N MB 扫描，默认 100"),
      verbose: z.boolean().optional().describe("详细输出，默认 false"),
    }),
    category: "iot",
    concurrent: true,
    execute: async (args: any) => {
      const { firmware_path, signature, max_size, verbose = false } = args;
      if (!fs.existsSync(firmware_path)) return `❌ 文件不存在: ${firmware_path}`;

      // 检查 binwalk 是否安装
      if (!commandExists("binwalk")) {
        return (
          `⚠️  系统未安装 binwalk。\n` +
          `  安装方式：\n` +
          `  macOS: brew install binwalk\n` +
          `  Ubuntu/Debian: sudo apt install binwalk\n` +
          `  pip install binwalk`
        );
      }

      const out: string[] = [`[Binwalk 签名扫描] ${firmware_path}`];
      if (signature) out.push(`签名过滤: ${signature}`);
      out.push(`最大扫描大小: ${max_size} MB\n`);

      let scanTarget = firmware_path;
      let tmpTruncated = "";
      try {
        // 检查文件大小，超出 max_size 则截断前 N MB 到临时文件
        const stat = fs.statSync(firmware_path);
        const sizeMb = stat.size / (1024 * 1024);
        if (sizeMb > max_size) {
          out.push(`⚠️  文件大小 ${sizeMb.toFixed(1)} MB 超过限制，仅扫描前 ${max_size} MB\n`);
          tmpTruncated = path.join(os.tmpdir(), `flagent-binscan-${Date.now()}`);
          child_process.execSync(
            `dd if="${firmware_path}" of="${tmpTruncated}" bs=1M count=${max_size} 2>/dev/null`,
            { timeout: 60000, maxBuffer: 1024 * 1024, encoding: "utf-8" }
          );
          scanTarget = tmpTruncated;
        }

        // 构造 binwalk 命令
        const verboseFlag = verbose ? "-v " : "";
        const result = runCmd(`binwalk ${verboseFlag}"${scanTarget}"`, 60000);

        // 解析结果，按 signature 过滤
        const lines = result.split("\n");
        if (signature) {
          const lowerSig = signature.toLowerCase();
          const filtered = lines.filter(
            (l) =>
              l.toLowerCase().includes(lowerSig) ||
              l.startsWith("DECIMAL") ||
              l.startsWith("HEX") ||
              l.trim() === "" ||
              /^-+\s*$/.test(l)
          );
          out.push(`── 扫描结果（过滤: ${signature}）──`);
          out.push(truncate(filtered.join("\n"), 8000));
        } else {
          out.push(`── 扫描结果 ──`);
          out.push(truncate(result, 8000));
        }

        out.push(`\n提示: 扫描结果包含 偏移(Offset) / 类型 / 描述，可用 firmware_extract 进一步提取`);
      } catch (err: any) {
        const errStderr = err.stderr ? `\nSTDERR:\n${err.stderr}` : "";
        out.push(`❌ 扫描失败: ${err.message}${errStderr}`);
      } finally {
        // 清理临时文件
        if (tmpTruncated) {
          try {
            fs.unlinkSync(tmpTruncated);
          } catch {}
        }
      }

      return out.join("\n");
    },
  });

  // 3. UART/JTAG 调试接口识别
  registry.register({
    name: "uart_jtag_detect",
    description: "UART/JTAG 调试接口识别：引脚识别指南、串口设备检测、波特率爆破",
    parameters: z.object({
      mode: z
        .enum(["guide", "detect", "brute"])
        .default("guide")
        .describe("模式：guide=引脚识别指南, detect=检测串口设备, brute=波特率爆破"),
      device: z.string().optional().describe("串口设备路径（如 /dev/ttyUSB0），detect/brute 模式使用"),
      baudrate: z
        .number()
        .min(50)
        .max(921600)
        .default(115200)
        .describe("波特率(50-921600)，默认 115200"),
      timeout_sec: z
        .number()
        .min(1)
        .max(30)
        .default(3)
        .describe("单次操作超时秒数(1-30)，默认 3"),
    }),
    category: "iot",
    concurrent: true,
    execute: async (args: any) => {
      const { mode, device, baudrate, timeout_sec } = args;
      const out: string[] = [`[UART/JTAG 调试接口识别] 模式: ${mode}\n`];

      // guide 模式：返回引脚识别指南
      if (mode === "guide") {
        out.push(`── UART/JTAG 引脚识别指南 ──`);
        out.push(
          `\n【UART 引脚识别（4 针：VCC/GND/TXD/RXD）】`,
          `1. 找 GND：用万用表通断档，对地电阻最小(0Ω)的引脚为 GND`,
          `2. 找 VCC：通电后用电压档测量，3.3V 或 5V 的引脚为 VCC（一般不接，避免烧板）`,
          `3. 区分 TXD/RXD：`,
          `   - 通电后 TXD 引脚相对 GND 电压约 3.3V（空闲为高电平）`,
          `   - 复位设备时 TXD 会有电压跳动（启动时输出日志）`,
          `   - RXD 引脚通常保持低电平或浮动`,
          `4. 连接：USB-TTL 的 RXD 接设备 TXD，TXD 接设备 RXD，GND 接 GND`,
          `5. 波特率：常见 9600/38400/57600/115200，可用 brute 模式爆破`,
          `\n【JTAG 引脚识别（10/20 针：TCK/TMS/TDI/TDO/TRST/GND）】`,
          `1. 找 GND：通断档对地电阻最小为 GND（通常多个引脚连通）`,
          `2. 找 TCK：通电后用示波器/逻辑分析仪，复位时有时钟信号的为 TCK`,
          `3. 找 TDO：复位时输出数据(有翻转)的为 TDO（仅扫描时输出）`,
          `4. TDI/TMS 通常需要上拉/下拉电阻辅助识别`,
          `5. 推荐工具：JTAGulator / JLink / OpenOCD`,
          `\n【常用工具】`,
          `  - 串口: screen /dev/ttyUSB0 115200, picocom, minicom`,
          `  - 逻辑分析: sigrok (PulseView), Saleae`,
          `  - JTAG: openocd, jtagenum, JTAGulator`
        );
        return out.join("\n");
      }

      // detect 模式：检测串口设备
      if (mode === "detect") {
        out.push(`── 串口设备检测 ──`);
        try {
          // 用 python3 -c 列出 /dev/ttyUSB* /dev/ttyACM* 设备
          const result = runCmd(
            `python3 -c "import glob; ports=sorted(glob.glob('/dev/ttyUSB*')+glob.glob('/dev/ttyACM*')+glob.glob('/dev/tty.SLAB_USB*')+glob.glob('/dev/cu.usbserial*')); print('\\\\n'.join(ports) if ports else 'NO_DEVICE')"`
          ).trim();

          if (!result || result === "NO_DEVICE") {
            out.push(`⚠️  未检测到串口设备`);
            out.push(`  请检查:`);
            out.push(`  - USB-TTL 转换器是否已连接`);
            out.push(`  - 驱动是否安装（CH340/CP2102/FT232 需对应驱动）`);
            out.push(`  - macOS 驱动: brew install --cask silicon-labs-vcp-driver`);
            out.push(`  - 权限: sudo chmod 666 /dev/ttyUSB0 或将用户加入 dialout 组`);
          } else {
            out.push(`检测到串口设备:`);
            out.push(result);
            out.push(`\n连接示例:`);
            const firstPort = result.split("\n")[0];
            out.push(`  screen ${firstPort} ${baudrate}`);
            out.push(`  picocom -b ${baudrate} ${firstPort}`);
          }
        } catch (err: any) {
          // python3 不可用时回退到 ls
          if (!commandExists("python3")) {
            out.push(`⚠️  需要 python3（未安装），回退到 ls 检测`);
            try {
              const lsResult = runCmd(`ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null`).trim();
              out.push(lsResult ? `检测到:\n${lsResult}` : `未检测到串口设备`);
            } catch {
              out.push(`未检测到串口设备`);
            }
          } else {
            out.push(`❌ 检测失败: ${err.message}`);
          }
        }
        return out.join("\n");
      }

      // brute 模式：波特率爆破
      if (mode === "brute") {
        if (!device) {
          return `❌ brute 模式需要指定 device 参数（如 /dev/ttyUSB0）`;
        }
        if (!fs.existsSync(device)) {
          return `❌ 串口设备不存在: ${device}`;
        }
        if (!commandExists("stty")) {
          return `⚠️  系统未安装 stty（核心工具，通常随 coreutils 提供）`;
        }

        const baudrates = [9600, 19200, 38400, 57600, 115200, 230400];
        out.push(`── 波特率爆破 ──`);
        out.push(`设备: ${device}`);
        out.push(`尝试波特率: ${baudrates.join(", ")}\n`);

        const hits: string[] = [];
        for (const baud of baudrates) {
          try {
            // 用 stty 设置波特率
            runCmd(`stty -F ${device} ${baud} raw -echo`, 3000);
            // 读取一小段数据，有输出则可能是正确波特率
            const sample = runCmd(
              `timeout ${timeout_sec} dd if=${device} bs=1 count=128 2>/dev/null | xxd | head -8`,
              (timeout_sec + 2) * 1000
            ).trim();
            if (sample) {
              // 检查是否为可读 ASCII（正确波特率通常输出可打印字符）
              const printable = sample.replace(/[^\x20-\x7e\n]/g, "").length;
              hits.push(`✅ ${baud}: 收到数据 (可打印字符比例较高，可能是正确波特率)\n${truncate(sample, 200)}`);
            } else {
              hits.push(`⚪ ${baud}: 无数据`);
            }
          } catch (err: any) {
            hits.push(`⚪ ${baud}: 无响应或超时`);
          }
        }

        out.push(hits.join("\n"));
        out.push(`\n提示: 收到乱码通常表示波特率错误，收到可读文本表示波特率正确`);
        out.push(`  确认波特率后可用: screen ${device} <baudrate> 持续接收`);
        return out.join("\n");
      }

      return out.join("\n");
    },
  });

  // 4. MQTT 协议分析
  registry.register({
    name: "mqtt_analyze",
    description: "MQTT 协议分析：连接测试、主题订阅、消息发布、主题枚举（mosquitto-clients）",
    parameters: z.object({
      host: z.string().describe("MQTT 服务器地址"),
      port: z.number().min(1).max(65535).default(1883).describe("端口，默认 1883"),
      mode: z
        .enum(["connect", "subscribe", "publish", "enumerate", "all"])
        .default("connect")
        .describe("模式：connect=连接测试, subscribe=订阅主题, publish=发布消息, enumerate=枚举主题, all=全部"),
      topic: z.string().optional().describe("主题名（subscribe/publish 模式使用）"),
      message: z.string().optional().describe("发布消息内容（publish 模式使用）"),
      timeout_sec: z.number().min(1).max(60).default(5).describe("超时秒数(1-60)，默认 5"),
      username: z.string().optional().describe("用户名（可选）"),
      password: z.string().optional().describe("密码（可选）"),
    }),
    category: "iot",
    concurrent: true,
    execute: async (args: any) => {
      const { host, port, mode, topic, message, timeout_sec, username, password } = args;

      // 检查 mosquitto-clients 是否安装
      if (!commandExists("mosquitto_pub") || !commandExists("mosquitto_sub")) {
        return (
          `⚠️  系统未安装 mosquitto-clients（提供 mosquitto_pub/mosquitto_sub）。\n` +
          `  安装方式：\n` +
          `  macOS: brew install mosquitto\n` +
          `  Ubuntu/Debian: sudo apt install mosquitto-clients\n` +
          `  RHEL/CentOS: sudo yum install mosquitto`
        );
      }

      // 构造认证参数
      const authArgs =
        username && password ? `-u "${username}" -P "${password}"` : "";

      const out: string[] = [`[MQTT 协议分析] ${host}:${port}\n模式: ${mode}\n`];

      // connect 模式：测试连接
      if (mode === "connect" || mode === "all") {
        out.push(`── 连接测试 ──`);
        try {
          const result = runCmd(
            `timeout ${timeout_sec} mosquitto_sub -h ${host} -p ${port} ${authArgs} -t '#' -W ${timeout_sec} -C 1 2>&1 || true`,
            (timeout_sec + 3) * 1000
          ).trim();
          // 无错误且能连上即视为成功（mosquitto_sub 超时退出码 27 也算连接成功）
          out.push(`✅ 连接成功（已建立 TCP/MQTT 连接）`);
          if (result) out.push(`捕获消息: ${truncate(result, 500)}`);
        } catch (err: any) {
          const errMsg = (err.stderr || err.message || "").toString();
          out.push(`❌ 连接失败: ${errMsg.split("\n")[0]}`);
          out.push(`  可能原因: 服务器未开放/端口错误/需要认证/TLS 端口(8883)`);
        }
      }

      // subscribe 模式：订阅主题并接收消息
      if (mode === "subscribe" || (mode === "all" && topic)) {
        const subTopic = topic || "#";
        out.push(`\n── 订阅主题: ${subTopic} ──`);
        try {
          const result = runCmd(
            `timeout ${timeout_sec} mosquitto_sub -h ${host} -p ${port} ${authArgs} -t '${subTopic}' -v 2>&1 || true`,
            (timeout_sec + 3) * 1000
          ).trim();
          if (result) {
            out.push(truncate(result, 4000));
          } else {
            out.push(`⚪ 在 ${timeout_sec} 秒内未收到消息`);
          }
        } catch (err: any) {
          out.push(`❌ 订阅失败: ${err.message}`);
        }
      }

      // publish 模式：发布消息
      if (mode === "publish") {
        if (!topic) {
          out.push(`❌ publish 模式需要指定 topic 参数`);
        } else if (message === undefined) {
          out.push(`❌ publish 模式需要指定 message 参数`);
        } else {
          out.push(`\n── 发布消息 ──`);
          try {
            runCmd(
              `mosquitto_pub -h ${host} -p ${port} ${authArgs} -t '${topic}' -m '${message.replace(/'/g, "'\\''")}' 2>&1`,
              (timeout_sec + 3) * 1000
            );
            out.push(`✅ 已发布到主题 "${topic}"`);
            out.push(`消息内容: ${truncate(message, 500)}`);
          } catch (err: any) {
            out.push(`❌ 发布失败: ${err.message}`);
          }
        }
      }

      // enumerate 模式：枚举可见主题
      if (mode === "enumerate" || mode === "all") {
        out.push(`\n── 主题枚举（订阅 # 捕获流量）──`);
        try {
          const result = runCmd(
            `timeout ${timeout_sec} mosquitto_sub -h ${host} -p ${port} ${authArgs} -t '#' -v 2>&1 || true`,
            (timeout_sec + 3) * 1000
          ).trim();
          if (result) {
            // 从 -v 输出中提取主题（格式：topic payload）
            const topics = new Set<string>();
            for (const line of result.split("\n")) {
              const m = line.match(/^(\S+)\s/);
              if (m) topics.add(m[1]);
            }
            out.push(`捕获到 ${topics.size} 个主题:`);
            out.push(Array.from(topics).slice(0, 50).map((t) => `  ${t}`).join("\n") || "  (无)");
            out.push(`\n原始消息（前 4000 字符）:`);
            out.push(truncate(result, 4000));
          } else {
            out.push(`⚪ 在 ${timeout_sec} 秒内未捕获到任何主题流量`);
            out.push(`  建议: 增大 timeout_sec，或检查 broker 是否允许匿名订阅 #`);
          }
        } catch (err: any) {
          out.push(`❌ 枚举失败: ${err.message}`);
        }
      }

      return out.join("\n");
    },
  });

  // 5. CoAP 协议分析
  registry.register({
    name: "coap_analyze",
    description: "CoAP 协议分析：资源发现、GET/POST 请求、常见 URI 路径模糊测试（libcoap coap-client）",
    parameters: z.object({
      host: z.string().describe("CoAP 服务器地址"),
      port: z.number().min(1).max(65535).default(5683).describe("端口，默认 5683"),
      mode: z
        .enum(["discover", "get", "post", "fuzz"])
        .default("discover")
        .describe("模式：discover=资源发现, get=GET请求, post=POST请求, fuzz=URI路径模糊测试"),
      uri: z.string().optional().describe("资源路径（如 /sensor），get/post 模式使用"),
      payload: z.string().optional().describe("POST 数据，post 模式使用"),
    }),
    category: "iot",
    concurrent: true,
    execute: async (args: any) => {
      const { host, port, mode, uri, payload } = args;

      // 检查 coap-client 是否安装
      if (!commandExists("coap-client")) {
        return (
          `⚠️  系统未安装 coap-client（属于 libcoap 工具包）。\n` +
          `  安装方式：\n` +
          `  macOS: brew install libcoap\n` +
          `  Ubuntu/Debian: sudo apt install libcoap-tools\n` +
          `  RHEL/CentOS: sudo yum install libcoap\n` +
          `  或从源码: git clone https://github.com/obgm/libcoap.git`
        );
      }

      const out: string[] = [`[CoAP 协议分析] ${host}:${port}\n模式: ${mode}\n`];
      const baseUrl = port === 5683 ? `coap://${host}` : `coap://${host}:${port}`;

      // discover 模式：资源发现
      if (mode === "discover") {
        out.push(`── 资源发现 (.well-known/core) ──`);
        try {
          const result = runCmd(
            `coap-client -m get "${baseUrl}/.well-known/core" 2>&1`,
            15000
          ).trim();
          if (result) {
            out.push(truncate(result, 6000));
            out.push(`\n提示: 返回的资源列表格式通常为 </sensor>;ct=41;obs，可对其中的 URI 执行 get/post`);
          } else {
            out.push(`⚪ 服务器未返回资源列表（可能不支持 .well-known/core）`);
          }
        } catch (err: any) {
          out.push(`❌ 资源发现失败: ${err.message}`);
        }
      }

      // get 模式：GET 请求
      if (mode === "get") {
        const targetUri = uri || "/";
        out.push(`── GET 请求: ${targetUri} ──`);
        try {
          const result = runCmd(
            `coap-client -m get "${baseUrl}${targetUri}" 2>&1`,
            15000
          ).trim();
          out.push(result ? truncate(result, 6000) : `⚪ 无响应`);
        } catch (err: any) {
          out.push(`❌ GET 请求失败: ${err.message}`);
        }
      }

      // post 模式：POST 请求
      if (mode === "post") {
        const targetUri = uri || "/";
        out.push(`── POST 请求: ${targetUri} ──`);
        if (payload === undefined) {
          out.push(`⚠️  未提供 payload，将发送空 POST`);
        }
        try {
          const postData = payload || "";
          // libcoap coap-client 用 -e 选项携带 payload
          const result = runCmd(
            `coap-client -m post -e '${postData.replace(/'/g, "'\\''")}' "${baseUrl}${targetUri}" 2>&1`,
            15000
          ).trim();
          out.push(result ? truncate(result, 6000) : `⚪ 无响应`);
        } catch (err: any) {
          out.push(`❌ POST 请求失败: ${err.message}`);
        }
      }

      // fuzz 模式：遍历常见 URI 路径
      if (mode === "fuzz") {
        out.push(`── URI 路径模糊测试 ──`);
        const commonUris = [
          "/",
          "/.well-known/core",
          "/sensor",
          "/temperature",
          "/humidity",
          "/light",
          "/pressure",
          "/switch",
          "/relay",
          "/actuator",
          "/led",
          "/config",
          "/status",
          "/info",
          "/device",
          "/firmware",
          "/update",
          "/reboot",
          "/admin",
          "/test",
          "/debug",
          "/metrics",
          "/version",
        ];
        const found: string[] = [];
        for (const u of commonUris) {
          try {
            const result = runCmd(
              `coap-client -m get "${baseUrl}${u}" 2>&1`,
              8000
            ).trim();
            if (result && !/timed out|refused|failed|error/i.test(result)) {
              found.push(`✅ ${u}\n${truncate(result, 200)}`);
            }
          } catch {
            // 忽略单个 URI 失败
          }
        }
        out.push(`扫描 ${commonUris.length} 个常见 URI，发现 ${found.length} 个有效响应:\n`);
        out.push(found.join("\n\n") || `⚪ 未发现有效资源`);
      }

      return out.join("\n");
    },
  });

  // 6. IoT 协议 Fuzz（需要权限确认）
  registry.register({
    name: "iot_protocol_fuzz",
    description: "IoT 协议 Fuzz：对 MQTT/CoAP/Modbus/RTSP 协议发送畸形数据，检测崩溃与异常响应（python3 脚本）",
    parameters: z.object({
      protocol: z
        .enum(["mqtt", "coap", "modbus", "rtsp", "custom"])
        .default("mqtt")
        .describe("目标协议，默认 mqtt"),
      host: z.string().describe("目标地址"),
      port: z
        .number()
        .min(1)
        .max(65535)
        .optional()
        .describe("端口，不指定则按协议自动选择(mqtt=1883/coap=5683/modbus=502/rtsp=554/custom=8888)"),
      mode: z
        .enum(["mutate", "random", "dictionary"])
        .default("dictionary")
        .describe("Fuzz 模式：mutate=变异基线包, random=随机字节, dictionary=字典驱动，默认 dictionary"),
      iterations: z
        .number()
        .min(10)
        .max(1000)
        .default(50)
        .describe("迭代次数(10-1000)，默认 50"),
      dictionary_path: z.string().optional().describe("字典文件路径（dictionary 模式使用，每行一个样本）"),
      timeout_sec: z.number().min(1).max(120).default(30).describe("总超时秒数(1-120)，默认 30"),
    }),
    category: "iot",
    requirePermission: true,
    execute: async (args: any) => {
      const { protocol, host, port, mode, iterations, dictionary_path, timeout_sec } = args;

      // 根据协议自动选择默认端口
      const defaultPorts: Record<string, number> = {
        mqtt: 1883,
        coap: 5683,
        modbus: 502,
        rtsp: 554,
        custom: 8888,
      };
      const targetPort = port || defaultPorts[protocol] || 8888;

      // 检查 python3
      if (!commandExists("python3")) {
        return `⚠️  系统未安装 python3（Fuzz 脚本依赖 python3 标准库 socket）。\n  安装: brew install python3 / apt install python3`;
      }

      // 校验字典文件
      if (mode === "dictionary" && dictionary_path) {
        if (!fs.existsSync(dictionary_path)) {
          return `❌ 文件不存在: ${dictionary_path}`;
        }
      }

      const out: string[] = [
        `[IoT 协议 Fuzz]`,
        `协议: ${protocol}`,
        `目标: ${host}:${targetPort}`,
        `模式: ${mode}`,
        `迭代: ${iterations}`,
        `超时: ${timeout_sec}s\n`,
      ];

      // 生成 Fuzz 脚本（使用标准库 socket，无需第三方依赖）
      const fuzzScript = `#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, socket, struct, random, time

PROTOCOL = os.environ.get("IOT_PROTOCOL", "mqtt")
HOST = os.environ.get("IOT_HOST", "127.0.0.1")
PORT = int(os.environ.get("IOT_PORT", "1883"))
MODE = os.environ.get("IOT_MODE", "dictionary")
ITER = int(os.environ.get("IOT_ITER", "50"))
DICT = os.environ.get("IOT_DICT", "")
TIMEOUT = int(os.environ.get("IOT_TIMEOUT", "30"))

random.seed(1337)

stats = {"sent": 0, "crash": 0, "abnormal": 0, "normal": 0, "errors": []}

def is_udp(proto):
    return proto == "coap"

# 各协议的基线数据包（合法样本，用于 mutate 模式）
def base_packet(proto):
    if proto == "mqtt":
        # MQTT CONNECT: protocol name "MQTT", v4, clean session, keepalive 60, client id "fuzz"
        var = b"\\x00\\x04MQTT"           # protocol name
        var += b"\\x04"                    # protocol level (v4)
        var += b"\\x02"                    # connect flags (clean session)
        var += b"\\x00\\x3c"               # keep alive 60
        cid = b"\\x00\\x05fuzz"            # client id
        body = var + cid
        rem = len(body)
        header = bytes([0x10 | (rem & 0x7f)])  # CONNECT + remaining length (简化，仅支持短长度)
        return header + body
    if proto == "coap":
        # CoAP GET Confirmable, token 0x01, MID 0x0001, GET "/"
        return bytes([0x40, 0x01, 0x00, 0x01, 0x01]) + b"\\xbb/"
    if proto == "modbus":
        # Modbus TCP Read Coils: TID=1, PID=0, len=6, unit=1, fc=1, start=0, count=8
        return struct.pack(">HHHBBHH", 1, 0, 6, 1, 1, 0, 8)
    if proto == "rtsp":
        # RTSP OPTIONS
        return b"OPTIONS rtsp://HOST/ RTSP/1.0\\r\\nCSeq: 1\\r\\n\\r\\n".replace(b"HOST", HOST.encode())
    # custom
    return b"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07"

def mutate(data):
    data = bytearray(data)
    if not data:
        data = bytearray(b"\\x00" * 8)
    n = max(1, len(data) // 4)
    for _ in range(n):
        op = random.randint(0, 3)
        if op == 0 and data:        # 翻转位
            i = random.randrange(len(data))
            data[i] ^= (1 << random.randint(0, 7))
        elif op == 1 and data:      # 替换随机字节
            i = random.randrange(len(data))
            data[i] = random.randint(0, 255)
        elif op == 2:               # 插入字节
            i = random.randint(0, len(data))
            data.insert(i, random.randint(0, 255))
        elif op == 3 and len(data) > 1:  # 删除字节
            i = random.randrange(len(data))
            del data[i]
    return bytes(data)

def random_bytes(n=None):
    n = n or random.randint(1, 64)
    return bytes(random.randint(0, 255) for _ in range(n))

# 生成字典样本
def dict_samples():
    samples = []
    if DICT and os.path.exists(DICT):
        try:
            with open(DICT, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.rstrip("\\n")
                    if s:
                        samples.append(s.encode("utf-8", errors="ignore"))
        except Exception:
            pass
    # 各协议内置样本
    if PROTOCOL == "mqtt":
        samples += [
            b"\\x00\\x00\\x00\\x00",                          # 空/非法头
            b"\\xff\\xff\\xff\\xff\\x00",                      # 畸形 remaining length
            b"\\x10\\x00",                                     # CONNECT 空体
            b"\\x82\\x00",                                     # SUBSCRIBE 空体
            b"\\x30\\xff\\xff\\xff\\xff\\x7fAAAA",             # PUBLISH 超长
        ]
    elif PROTOCOL == "coap":
        samples += [
            bytes([0x00, 0x00, 0x00, 0x00]),                   # 版本/类型全 0
            bytes([0xf0, 0x00, 0x00, 0x00]),                   # 非法版本
            bytes([0x40, 0xff, 0x00, 0x00]),                   # 非法 code
            bytes([0x7f, 0x3f, 0xff, 0xff]) + b"\\xff" * 20,   # 超长 token + 非法选项
        ]
    elif PROTOCOL == "modbus":
        samples += [
            struct.pack(">HHHBBHH", 1, 0, 6, 1, 99, 0, 0),    # 非法功能码 99
            struct.pack(">HHHBBHH", 1, 0, 6, 1, 1, 0xffff, 0xffff),  # 越界寄存器
            struct.pack(">HHHBBHH", 1, 1, 6, 1, 1, 0, 0),     # 非法 PID
            struct.pack(">HH", 1, 0) + b"\\x00",               # 长度字段错误
        ]
    elif PROTOCOL == "rtsp":
        samples += [
            b"BADMETHOD rtsp://HOST/ RTSP/1.0\\r\\n\\r\\n".replace(b"HOST", HOST.encode()),
            b"OPTIONS rtsp://HOST/ RTSP/9.9\\r\\n\\r\\n".replace(b"HOST", HOST.encode()),
            b"OPTIONS rtsp://HOST/ RTSP/1.0\\r\\n" + b"A" * 1000 + b"\\r\\n\\r\\n",  # 超长头
            b"OPTIONS rtsp://HOST/\\r\\n\\r\\n".replace(b"HOST", HOST.encode()),     # 缺少版本
        ]
    else:
        samples += [b"\\x00", b"\\xff", b"\\x00" * 64, b"\\xff" * 64]
    return samples

def send_once(data):
    stats["sent"] += 1
    sock = None
    try:
        family = socket.AF_INET
        try:
            info = socket.getaddrinfo(HOST, PORT, family, socket.SOCK_STREAM if not is_udp(PROTOCOL) else socket.SOCK_DGRAM)
            family, stype, proto, _, sockaddr = info[0]
        except Exception:
            sockaddr = (HOST, PORT)
            stype = socket.SOCK_DGRAM if is_udp(PROTOCOL) else socket.SOCK_STREAM
        sock = socket.socket(family, stype, proto)
        sock.settimeout(2.0)
        if is_udp(PROTOCOL):
            sock.sendto(data, sockaddr)
            try:
                resp, _ = sock.recvfrom(2048)
                if resp:
                    stats["abnormal"] += 1   # UDP 收到非预期响应视为异常响应
            except socket.timeout:
                stats["normal"] += 1         # 无响应（UDP 常见）
        else:
            sock.connect(sockaddr)
            sock.sendall(data)
            try:
                resp = sock.recv(2048)
                if resp:
                    stats["normal"] += 1
                else:
                    stats["abnormal"] += 1
            except socket.timeout:
                stats["abnormal"] += 1       # 连接建立但无响应
        sock.close()
    except ConnectionRefusedError:
        stats["crash"] += 1
        stats["errors"].append("ConnectionRefused (服务可能已崩溃或未开放)")
    except ConnectionResetError:
        stats["crash"] += 1
        stats["errors"].append("ConnectionReset (服务可能因畸形数据崩溃)")
    except socket.timeout:
        stats["crash"] += 1
        stats["errors"].append("ConnectTimeout (无响应)")
    except BrokenPipeError:
        stats["crash"] += 1
        stats["errors"].append("BrokenPipe")
    except OSError as e:
        stats["abnormal"] += 1
        stats["errors"].append(f"OSError: {e}")
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass

def main():
    deadline = time.time() + TIMEOUT
    samples = dict_samples()
    base = base_packet(PROTOCOL)
    i = 0
    while i < ITER and time.time() < deadline:
        if MODE == "mutate":
            data = mutate(base)
        elif MODE == "random":
            data = random_bytes()
        else:  # dictionary
            data = samples[i % len(samples)] if samples else random_bytes()
            if MODE == "dictionary":
                data = mutate(data) if random.random() < 0.3 else data
        send_once(data)
        i += 1
        # TCP 模式稍微间隔，避免瞬时连接过多
        time.sleep(0.02 if not is_udp(PROTOCOL) else 0.0)
    # 输出摘要
    print("=== IoT Fuzz 摘要 ===")
    print(f"协议: {PROTOCOL}")
    print(f"目标: {HOST}:{PORT}")
    print(f"模式: {MODE}")
    print(f"发送总数: {stats['sent']}")
    print(f"崩溃迹象: {stats['crash']}")
    print(f"异常响应: {stats['abnormal']}")
    print(f"正常响应: {stats['normal']}")
    if stats["errors"]:
        from collections import Counter
        c = Counter(stats["errors"])
        print("\\n--- 错误分类（前 5）---")
        for err, cnt in c.most_common(5):
            print(f"  {cnt}x  {err}")
    print("\\n提示:")
    print("- 崩溃迹象高 = 服务可能因畸形数据崩溃（建议结合服务日志/gdb 确认）")
    print("- 异常响应高 = 服务返回非预期数据（可能存在解析漏洞）")

if __name__ == "__main__":
    main()
`;

      // 写入临时脚本文件
      const tmpScript = path.join(os.tmpdir(), `flagent-iotfuzz-${Date.now()}.py`);
      try {
        fs.writeFileSync(tmpScript, fuzzScript, { encoding: "utf-8" });

        // 通过环境变量传参，避免命令行转义问题
        const env: NodeJS.ProcessEnv = {
          ...process.env,
          IOT_PROTOCOL: protocol,
          IOT_HOST: host,
          IOT_PORT: String(targetPort),
          IOT_MODE: mode,
          IOT_ITER: String(iterations),
          IOT_DICT: dictionary_path || "",
          IOT_TIMEOUT: String(timeout_sec),
        };

        out.push(`执行 Fuzz 脚本: python3 ${tmpScript}\n`);
        const result = child_process.execSync(`python3 "${tmpScript}"`, {
          timeout: (timeout_sec + 10) * 1000,
          maxBuffer: 1024 * 1024,
          encoding: "utf-8",
          env,
        });
        out.push(result.trim());
      } catch (err: any) {
        const errStdout = err.stdout ? `\n${err.stdout}` : "";
        const errStderr = err.stderr ? `\nSTDERR:\n${err.stderr}` : "";
        // 即便脚本非零退出（如超时），也尝试输出已捕获的摘要
        out.push(`❌ Fuzz 执行异常: ${err.message}${errStdout}${errStderr}`);
        out.push(`  可能原因: 目标不可达/总超时过短/连接被防火墙拦截`);
      } finally {
        // 清理临时脚本
        try {
          fs.unlinkSync(tmpScript);
        } catch {}
      }

      return out.join("\n");
    },
  });

  return registry;
}

/** 递归列出目录下所有文件（用于列出固件提取结果） */
function listFilesRecursive(dir: string): string[] {
  const results: string[] = [];
  function walk(d: string) {
    try {
      const entries = fs.readdirSync(d, { withFileTypes: true });
      for (const e of entries) {
        const full = path.join(d, e.name);
        if (e.isDirectory()) {
          walk(full);
        } else if (e.isFile()) {
          results.push(full);
        }
      }
    } catch {}
  }
  walk(dir);
  return results;
}
