# IDA Auto MCP

[English](#english) | [中文](#中文)

---

## English

Headless IDA Pro MCP server that enables AI agents to **automatically** open, analyze, and query multiple binary files — no manual IDA GUI interaction required.

### Why This Project?

IDA Auto MCP is a small MCP server built directly on IDA's headless `idalib` library. The AI agent opens binaries itself with `open_binary` (no IDA window, no plugin to start) and can track several of them as sessions, switching between them as it works, which helps with programs made of an executable and several DLLs. Only the active database is open at a time: switching saves and closes it, then reopens the other one.

It is not the only headless option: [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) also ships an idalib-based server with multi-binary support, and [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) is a headless server written in Rust. IDA Auto MCP aims to stay small and easy to audit: a single Python process, no third-party dependencies besides IDA's own `idapro` package, and an implicit active session so tools don't take a database argument.

### Key Features

- **Fully Automatic** — AI agents call `open_binary("path/to/file.dll")` to start analysis, no human in the loop
- **Multi-Binary Sessions** — Track several binaries as sessions and switch between them (only one database is open at a time; switching saves it and reopens the other one without re-running analysis)
- **Background Analysis** — `open_binary` waits for IDA's auto-analysis for at most `--analysis-wait` seconds (30 by default) and the analysis continues between tool calls, so a binary that takes hours to analyze can be queried right away
- **Headless** — Uses `idalib` (IDA as a library), no GUI needed
- **55 Analysis Tools** — Decompile, disassemble, xrefs, strings, imports, types, search, rename, patching, and more
- **Read-Only by Default** — Tools that modify the database or run arbitrary code are off until you enable them
- **Time Limits and Cancellation** — A runaway tool call is stopped after `--timeout` seconds, or as soon as the client cancels it
- **Careful with Databases** — Refuses a database that another IDA has open, and backs up what a crash left behind before IDA discards it
- **Raw Firmware** — `open_binary` takes the processor, file type, base address and entry point of a raw blob
- **MCP Standard** — Works with Claude Desktop, Claude Code, Codex, and any MCP client; tools carry MCP annotations (`readOnlyHint`, `destructiveHint`) and the server sends usage instructions
- **Stdio + HTTP** — Stdio transport for MCP clients, token-protected HTTP for debugging

### Prerequisites

1. **IDA Pro 9.0+** (with valid license), tested with IDA 9.3 and 9.5. On IDA 9.5 the server uses the address-based APIs that replace the ones 9.5 deprecates (`get_func`, `getseg`, the `func_t`-based frame functions), so it prints no `DeprecationWarning`; earlier versions keep using the original APIs.
2. **idapro Python package** — Hex-Rays' loader for idalib. Installing this project pulls it from PyPI; you can also install the wheel shipped with IDA Pro:
   ```bash
   pip install "<IDA_INSTALL_DIR>/idalib/python/idapro-<version>-py3-none-any.whl"
   ```
   The file name depends on the IDA release, for example `idapro-0.0.7-py3-none-any.whl` in IDA 9.3 and `idapro-0.0.10-py3-none-any.whl` in IDA 9.5. After upgrading IDA, point `IDADIR` (or `--ida-dir`) at the new installation.
3. **IDADIR** — set via environment variable or `--ida-dir` flag, or configure idalib once with `python "<IDA_INSTALL_DIR>/idalib/python/py-activate-idalib.py"`

### Installation

```bash
pip install ida-auto-mcp
```

This installs the `ida-auto-mcp` command together with Hex-Rays' `idapro`
package. With [uv](https://github.com/astral-sh/uv) you can skip the
installation: `uvx ida-auto-mcp` runs the server in an environment that uv
manages, and `uvx ida-auto-mcp@latest` also picks up new releases.

To work on the code, install it from a clone instead:

```bash
git clone https://github.com/mufeng05/ida-auto-mcp.git
cd ida-auto-mcp
pip install -e .
```

### Quick Start

The configurations below run `python -m ida_auto_mcp` with the Python you
installed the package into. To use uv instead, set the command to `uvx` and
put `ida-auto-mcp` before the other arguments.

#### Claude Code plugin

This repository is also a Claude Code plugin marketplace. With
[uv](https://github.com/astral-sh/uv) on your `PATH` and IDA's location in
`IDADIR` (or configured with `py-activate-idalib.py`), install the plugin:

```bash
claude plugin marketplace add mufeng05/ida-auto-mcp
claude plugin install ida-auto-mcp@ida-auto-mcp
```

On Claude Code 2.1.275 or later, `/plugin install ida-auto-mcp --marketplace mufeng05/ida-auto-mcp`
does both in one step. The plugin runs the server with its defaults: read-only
tools and a 300-second time limit. For write tools or `run_script`, configure
the server yourself as shown below.

#### Codex (`~/.codex/config.toml`)

Codex reads MCP server settings from `~/.codex/config.toml` (or from
`.codex/config.toml` in a trusted project). Add:

```toml
[mcp_servers.ida-auto-mcp]
command = "python"
args = ["-m", "ida_auto_mcp"]
startup_timeout_sec = 30
tool_timeout_sec = 600

[mcp_servers.ida-auto-mcp.env]
IDADIR = "C:/Program Files/IDA Pro"
```

You can register the same server with the Codex CLI instead:

```bash
codex mcp add ida-auto-mcp --env "IDADIR=C:/Program Files/IDA Pro" -- python -m ida_auto_mcp
codex mcp list
```

Replace the IDA path with the installation path on your machine. If Codex
cannot find `python`, set `command` to the Python executable's absolute path,
for example `C:/Python310/python.exe`. Start a new Codex session after changing
the configuration; restart the desktop app or IDE extension when using those
clients. See the [Codex MCP documentation](https://developers.openai.com/codex/mcp/)
for additional configuration options.

#### Claude Code

Register the server with the Claude Code CLI (add `-s user` to make it
available in every project):

```bash
claude mcp add ida -e "IDADIR=C:/Program Files/IDA Pro" -- uvx ida-auto-mcp
```

Or add it to `~/.claude.json` yourself:

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### Command Line

```bash
# Start server (stdio mode, default; read-only tools only)
python -m ida_auto_mcp

# Pre-load a binary on startup
python -m ida_auto_mcp C:/samples/target.exe

# Also enable the tools that modify the database, and run_script
python -m ida_auto_mcp --allow-write --allow-script

# HTTP mode for debugging (prints a bearer token on startup)
python -m ida_auto_mcp --transport http --port 8765

# Allow 10 minutes per tool call instead of 5, and log every call
python -m ida_auto_mcp --timeout 600 --trace C:/temp/ida-auto-mcp.jsonl

# open_binary returns as soon as the file is loaded; IDA analyzes it in the background
python -m ida_auto_mcp --analysis-wait 0

# Verbose logging
python -m ida_auto_mcp -v
```

### Permissions

By default the server only exposes tools that read the database. Two flags enable the rest:

| Flag | Enables |
|------|---------|
| `--allow-write` | Tools that modify the IDA database or save it to disk: `save_database`, `rename_address`, `set_comment`, `append_comment`, `set_function_type`, `declare_type`, `apply_type`, `enum_upsert`, `infer_types`, `declare_stack_var`, `delete_stack_var`, `define_function`, `define_code`, `undefine_code`, `patch_bytes`, `patch_asm` |
| `--allow-script` | `run_script`, which executes arbitrary Python with the server's privileges |

Add the flags to `args` in your MCP client configuration, for example `"args": ["-m", "ida_auto_mcp", "--allow-write"]`. Disabled tools are not listed, and calling one returns an error that names the flag. As IDA always does, opening a binary still creates database files next to it, and closing or switching sessions saves them.

Keep both flags off while analyzing untrusted samples: strings and names inside a binary can carry prompt-injection text aimed at the agent.

Each tool also carries MCP annotations: read-only tools are marked `readOnlyHint`, and the write tools and `run_script` are marked `destructiveHint`, so clients can tell them apart.

### Background Analysis

IDA's auto-analysis of a large or obfuscated binary can take hours, and idalib's own wait for it cannot be interrupted. The server therefore runs the analysis in small steps. `open_binary` waits for it for at most `--analysis-wait` seconds (30 by default; `0` returns as soon as the file is loaded). After that the server continues the analysis whenever no request is waiting, in slices of about 50 ms, so requests are answered between two slices. A rare step takes a few seconds and then delays the next request.

Until the analysis is complete, function lists, cross-references and pseudocode can be incomplete and change as it progresses. `open_binary` and `get_database_info` report `analysis`: whether it is `complete`, its current `stage` and `address`, and the number of `functions` found so far. Sessions report `analysis` as `running`, `paused` (another session is active; it resumes when this one is again), `off` or `complete`. `wait_analysis(timeout)` waits for up to `timeout` seconds (60 by default, `0` until the analysis finishes) and reports the progress; it can be cancelled. With `auto_analysis=false`, nothing is analyzed until `wait_analysis` runs the analysis. Analysis that is still pending is saved with the database when you switch sessions.

Results derived from the analysis follow it: once it has changed the database, functions are decompiled again instead of coming from the decompiler's cache. `list_strings` and `search_strings` keep IDA's string list between calls, since building it scans the whole database; the list is rebuilt at most once a minute while analysis runs, and once more when it finishes.

### Time Limits and Cancellation

A tool call may run for `--timeout` seconds (300 by default, `0` for no limit). After that the server stops it and returns an error that suggests narrowing the request. When the client cancels a call over stdio (`notifications/cancelled`, for example when you interrupt the agent), the server stops it the same way and sends no result. Python code stops at once; a call busy inside one IDA function stops when that function returns. On IDA 9.5 and later the decompiler gets the same limit and stops by itself. `wait_analysis` stops between two analysis steps, and ends a little before the time limit to report the progress. Opening, switching, closing and saving databases are never interrupted, so a database is never left half opened or half saved.

`--trace FILE` appends one JSON line per tool call (tool, arguments, duration, error), which helps to see what an agent did and where the time went.

### Opening Databases

Before opening a database, the server looks at its files. If another IDA instance has it open, for example in the IDA GUI, `open_binary` refuses with a clear error and the current session stays active. If IDA stopped without closing it (a crash), IDA would silently reopen the last saved copy and discard the files left behind; the server first copies them to `<name>.i64.crash-<time>/` and says so in the `open_binary` result.

For raw firmware and other files IDA can't identify, `open_binary` takes loader options: `processor` (for example `arm`), `file_type` (for example `Binary file`), `base_address` and `entry_point`. They apply when IDA creates the file's database and are ignored once it exists.

### Tools (55 total)

Tools marked *(write)* need `--allow-write`; *(script)* needs `--allow-script`.

#### Session
| Tool | Description |
|------|-------------|
| `open_binary` | Open a binary for analysis (waits up to `--analysis-wait` seconds for auto-analysis, which then continues in the background; loader options for raw firmware) |
| `close_binary` | Close a session |
| `switch_binary` | Switch active session |
| `list_sessions` | List all open sessions |
| `get_current_session` | Get active session info |

#### Database
| Tool | Description |
|------|-------------|
| `get_database_info` | Binary metadata (filename, arch, imagebase, MD5, SHA256, file size) |
| `wait_analysis` | Run auto-analysis until it finishes or a timeout passes, and report its progress |
| `save_database` | Save IDA database to disk *(write)* |

#### Analysis
| Tool | Description |
|------|-------------|
| `list_functions` | List/filter functions with pagination |
| `get_function_info` | Detailed function info (prototype, size) |
| `decompile_function` | Hex-Rays decompilation to C pseudocode |
| `disassemble_function` | Assembly disassembly |
| `get_xrefs_to` | Cross-references TO an address |
| `get_xrefs_from` | Cross-references FROM an address |
| `export_function` | Export function as C header or full decompiled code |

#### Data
| Tool | Description |
|------|-------------|
| `list_strings` | Strings in the binary; IDA 9.5 synthetic strings, which exist only in the code, are marked `synthetic` |
| `search_strings` | Regex search in strings |
| `list_imports` | Imported functions by module |
| `list_exports` | Exported symbols |
| `list_segments` | Memory segments/sections |
| `list_entrypoints` | List binary entry points |
| `get_globals` | List global variables |

#### Control Flow
| Tool | Description |
|------|-------------|
| `get_callers` | Find all functions that call a given function |
| `get_callees` | Find all functions called by a given function |
| `get_callgraph` | Build call graph with depth control (BFS) |
| `get_basic_blocks` | Get CFG basic blocks with type/successor/predecessor info |
| `get_address_info` | Resolve address to segment/function/symbol context |
| `find_paths` | Find control-flow paths between two addresses in the same function |
| `trace_data_flow` | BFS data flow tracing via xrefs (forward/backward) |

#### Types & Structs
| Tool | Description |
|------|-------------|
| `list_structs` | List structs/unions in the database |
| `get_struct_info` | Get struct details with all member fields |
| `list_local_types` | List all local types (structs, enums, typedefs) with filtering |
| `type_inspect` | Inspect a named type in detail (size, kind, declaration, members) |
| `declare_type` | Declare C type definition in local type library *(write)* |
| `apply_type` | Apply type to address (function, global, etc.) *(write)* |
| `enum_upsert` | Create or extend an enum type, optionally a bitmask enum (idempotent) *(write)* |
| `infer_types` | Auto-infer and apply type at address (Hex-Rays/heuristic) *(write)* |
| `xrefs_to_field` | Get cross-references to a specific struct field member |
| `get_stack_frame` | Get stack frame layout (locals, args); each member's `fp_offset` (frame-pointer-relative) is the offset the stack variable tools take |
| `declare_stack_var` | Create or rename the stack variable at an `fp_offset` *(write)* |
| `delete_stack_var` | Delete the stack variable at an `fp_offset` from a function frame *(write)* |

#### Code Definition
| Tool | Description |
|------|-------------|
| `define_function` | Define a function at an address *(write)* |
| `define_code` | Convert bytes to code instructions *(write)* |
| `undefine_code` | Undefine items back to raw bytes *(write)* |

#### Search
| Tool | Description |
|------|-------------|
| `search_bytes` | Byte pattern search with wildcards (`48 89 5C ?? 57`) |
| `find_insns` | Find instructions matching mnemonic/operand pattern (regex) |

#### Modify
| Tool | Description |
|------|-------------|
| `rename_address` | Rename function/address (auto-invalidates decompiler cache) *(write)* |
| `set_comment` | Set disassembly comment *(write)* |
| `append_comment` | Append comment without overwriting (auto-dedup) *(write)* |
| `set_function_type` | Set function prototype (auto-invalidates decompiler cache) *(write)* |
| `patch_bytes` | Patch bytes at an address (binary patching) *(write)* |
| `patch_asm` | Assemble instruction and patch at address *(write)* |

#### Memory Reading
| Tool | Description |
|------|-------------|
| `read_bytes` | Read raw bytes at address |
| `get_string_at` | Read null-terminated string at address |

#### Script
| Tool | Description |
|------|-------------|
| `run_script` | Execute arbitrary IDAPython code; variables persist between calls until another database opens, and a final expression's value is returned *(script)* |

### Multi-Binary Workflow Example

```
User: Analyze main.exe and its plugin.dll

AI: open_binary("C:/samples/main.exe")        → Opens & analyzes main.exe
AI: list_functions(filter_str="*LoadPlugin*")  → Finds LoadPlugin function
AI: decompile_function("LoadPlugin")           → Gets pseudocode
AI: open_binary("C:/samples/plugin.dll")       → Opens plugin.dll (new session)
AI: list_exports()                             → Lists DLL exports
AI: decompile_function("PluginInit")           → Decompiles export
AI: switch_binary("<main.exe session id>")     → Switches back to main.exe
AI: get_xrefs_to("0x401000")                  → Checks cross-references
```

### Architecture

```
ida_auto_mcp/
├── server.py        # CLI entry point, idapro initialization
├── mcp_server.py    # MCP protocol implementation (stdio + HTTP), time limits
├── _registry.py     # Global McpServer instance + tool decorators
├── session.py       # Multi-binary session management via idalib
├── analysis.py      # Runs IDA's auto-analysis in bounded steps
├── idb_files.py     # Checks a database's files before IDA opens it
└── tools.py         # 55 IDA analysis tools
```

The tests need no IDA installation. They cover tool permissions, the HTTP checks, the protocol layer (version negotiation, annotations, time limits, cancellation, the trace, background work), `run_script`, the database file checks and loader options, and, with stand-ins for IDA's modules, the analysis steps, the caches they refresh and functions split into chunks:

```bash
python -m unittest discover -s tests -v
```

`tests/tool_metadata.json` is a snapshot of what the server advertises to clients. After an intentional change to a tool's name, description or parameters, regenerate it with `IDA_AUTO_MCP_UPDATE_SNAPSHOT=1 python -m unittest tests.test_tool_metadata`. GitHub Actions runs the tests on Windows and Linux. Publishing a GitHub release builds the package and uploads it to PyPI, once the repository is set up as a trusted publisher on PyPI (environment `pypi`).

### Security

- **HTTP transport** is meant for local debugging. It listens on 127.0.0.1, and every POST to `/mcp` needs `Authorization: Bearer <token>`. A random token is printed at startup; when you register the server in a client, set your own in the `IDA_AUTO_MCP_TOKEN` environment variable instead, because the random one changes on every start. Requests whose `Host` or `Origin` is not a loopback address are rejected, which blocks DNS rebinding and calls from web pages on other sites. `--host` changes this: bound to a specific address, the server also accepts that address as `Host` and `Origin`; bound to all interfaces (`0.0.0.0`), it accepts any `Host` and relies on the token alone. Either way it prints a warning, because the traffic is not encrypted. With Claude Code, for example: `claude mcp add --transport http ida http://127.0.0.1:8765/mcp --header "Authorization: Bearer <token>"`.
- **Untrusted samples:** analyze malware only inside an isolated VM. Everything the tools return from a sample (strings, names, decompiled code) is untrusted input to your agent.
- **Intended use:** software you own or are authorized to analyze, such as malware triage, vulnerability research and auditing your own builds and firmware. Don't use it to circumvent software licensing.
- Report vulnerabilities as described in [SECURITY.md](https://github.com/mufeng05/ida-auto-mcp/blob/master/SECURITY.md).

### Acknowledgements

- The MCP protocol layer (`mcp_server.py`) is adapted from [zeromcp](https://github.com/mrexodia/zeromcp) by Duncan Ogilvie (MIT License); see [THIRD_PARTY_NOTICES.md](https://github.com/mufeng05/ida-auto-mcp/blob/master/THIRD_PARTY_NOTICES.md).
- Many tool names and features follow [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
- The control-flow, struct and patching tools were first modeled on [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs).
- The database file checks and the way tool calls are interrupted follow Hex-Rays' [ida-nexus](https://github.com/HexRaysSA/ida-nexus) (MIT License), the library behind the official [IDA MCP server](https://github.com/HexRaysSA/ida-mcp).

### License

MIT, see [LICENSE](https://github.com/mufeng05/ida-auto-mcp/blob/master/LICENSE). IDA Pro itself requires a valid license.

---

## 中文

无界面 IDA Pro MCP 服务器，让 AI 智能体**自动**打开、分析和查询多个二进制文件——无需手动操作 IDA GUI。

### 为什么做这个项目？

IDA Auto MCP 是直接基于 IDA 无头分析库 `idalib` 的小型 MCP 服务器。AI 智能体自己调用 `open_binary` 打开二进制文件（不需要打开 IDA 界面，也不用启动插件），还可以把多个文件记录为会话并在它们之间切换，适合分析由一个主程序和多个 DLL 组成的软件。同一时刻只打开一个数据库：切换时会保存并关闭当前数据库，再重新打开目标数据库。

它不是唯一的无头方案：[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 同样提供基于 idalib、支持多文件的服务器，[ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) 是用 Rust 写的无头服务器。IDA Auto MCP 的目标是保持小巧、便于审计：单个 Python 进程，除 IDA 自带的 `idapro` 包外没有第三方依赖，并采用隐式的当前会话，调用工具时不需要传数据库参数。

### 核心特性

- **全自动** — AI 直接调用 `open_binary("path/to/file.dll")` 即可开始分析，无需人工干预
- **多文件会话** — 可将多个文件记录为会话并自由切换（同一时刻只打开一个数据库，切换时保存当前数据库并重新打开目标数据库，不会重新分析）
- **后台分析** — `open_binary` 最多等待 IDA 自动分析 `--analysis-wait` 秒（默认 30 秒），之后分析在工具调用的间隙继续进行，分析要跑几个小时的程序也能马上开始查询
- **无需 GUI** — 使用 `idalib`（IDA 库模式），不需要打开 IDA 界面
- **55 个分析工具** — 反编译、反汇编、交叉引用、字符串、导入表、类型系统、搜索、重命名、补丁等
- **默认只读** — 会修改数据库或执行任意代码的工具默认关闭，需要显式开启
- **超时与取消** — 失控的工具调用会在 `--timeout` 秒后停止，客户端取消时也会立即停止
- **谨慎对待数据库** — 拒绝打开正被其他 IDA 使用的数据库；IDA 丢弃崩溃残留文件之前先做备份
- **原始固件** — `open_binary` 可以指定原始数据块的处理器、文件类型、基址和入口点
- **MCP 标准协议** — 支持 Claude Desktop、Claude Code、Codex 及所有 MCP 客户端；工具带有 MCP 标注（`readOnlyHint`、`destructiveHint`），服务器会下发使用说明
- **双传输模式** — stdio 模式用于 MCP 客户端，带令牌认证的 HTTP 模式用于调试

### 前置要求

1. **IDA Pro 9.0+**（需要有效许可证），已在 IDA 9.3 和 9.5 上测试。在 IDA 9.5 上，服务器改用基于地址的新接口，替代 9.5 弃用的接口（`get_func`、`getseg`、基于 `func_t` 的栈帧函数等），因此不会输出 `DeprecationWarning`；更早的版本继续使用原有接口。
2. **idapro Python 包** — Hex-Rays 提供的 idalib 加载器。安装本项目时会自动从 PyPI 安装；也可以安装 IDA Pro 自带的 wheel：
   ```bash
   pip install "<IDA安装目录>/idalib/python/idapro-<版本>-py3-none-any.whl"
   ```
   文件名随 IDA 版本而变，例如 IDA 9.3 中为 `idapro-0.0.7-py3-none-any.whl`，IDA 9.5 中为 `idapro-0.0.10-py3-none-any.whl`。升级 IDA 后，请把 `IDADIR`（或 `--ida-dir`）指向新的安装目录。
3. **IDADIR** — 通过环境变量或 `--ida-dir` 参数设置 IDA 安装路径，也可以运行一次 `python "<IDA安装目录>/idalib/python/py-activate-idalib.py"` 为 idalib 配置好

### 安装

```bash
pip install ida-auto-mcp
```

这会安装 `ida-auto-mcp` 命令，以及 Hex-Rays 的 `idapro` 包。如果使用
[uv](https://github.com/astral-sh/uv)，可以不用安装：`uvx ida-auto-mcp`
会在 uv 管理的环境中运行服务器，`uvx ida-auto-mcp@latest` 还会自动使用新版本。

如需修改代码，请改为从克隆的仓库安装：

```bash
git clone https://github.com/mufeng05/ida-auto-mcp.git
cd ida-auto-mcp
pip install -e .
```

### 快速开始

下面的配置用安装了本包的 Python 运行 `python -m ida_auto_mcp`。如果改用 uv，
把命令设为 `uvx`，并把 `ida-auto-mcp` 放在其他参数之前即可。

#### Claude Code 插件

本仓库同时也是一个 Claude Code 插件 marketplace。确保
[uv](https://github.com/astral-sh/uv) 在 `PATH` 中，并已通过 `IDADIR`
（或 `py-activate-idalib.py`）配置好 IDA 路径，然后安装插件：

```bash
claude plugin marketplace add mufeng05/ida-auto-mcp
claude plugin install ida-auto-mcp@ida-auto-mcp
```

在 Claude Code 2.1.275 及以上版本中，`/plugin install ida-auto-mcp --marketplace mufeng05/ida-auto-mcp`
可以一步完成。插件以默认设置启动服务器：只提供只读工具，单次调用上限 300 秒。
如需写入类工具或 `run_script`，请按下文自行配置服务器。

#### Codex 配置 (`~/.codex/config.toml`)

Codex 从 `~/.codex/config.toml` 读取 MCP 服务器配置；也可以在受信任的项目中使用
项目级 `.codex/config.toml`。添加以下内容：

```toml
[mcp_servers.ida-auto-mcp]
command = "python"
args = ["-m", "ida_auto_mcp"]
startup_timeout_sec = 30
tool_timeout_sec = 600

[mcp_servers.ida-auto-mcp.env]
IDADIR = "C:/Program Files/IDA Pro"
```

也可以使用 Codex CLI 注册相同的服务器：

```bash
codex mcp add ida-auto-mcp --env "IDADIR=C:/Program Files/IDA Pro" -- python -m ida_auto_mcp
codex mcp list
```

请将 IDA 路径替换为本机的实际安装路径。如果 Codex 找不到 `python`，请将
`command` 改为 Python 可执行文件的绝对路径，例如 `C:/Python310/python.exe`。
修改配置后请新建 Codex 会话；使用桌面应用或 IDE 扩展时，请重启对应客户端。
更多配置选项请参阅 [Codex MCP 官方文档](https://developers.openai.com/codex/mcp/)。

#### Claude Code 配置

用 Claude Code CLI 注册服务器（加上 `-s user` 可在所有项目中使用）：

```bash
claude mcp add ida -e "IDADIR=C:/Program Files/IDA Pro" -- uvx ida-auto-mcp
```

也可以自行写入 `~/.claude.json`：

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### Claude Desktop 配置 (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### 命令行使用

```bash
# 启动服务器（stdio 模式，默认；只提供只读工具）
python -m ida_auto_mcp

# 启动时预加载一个文件
python -m ida_auto_mcp C:/samples/target.exe

# 同时开启修改数据库的工具和 run_script
python -m ida_auto_mcp --allow-write --allow-script

# HTTP 模式（调试用，启动时会打印 Bearer 令牌）
python -m ida_auto_mcp --transport http --port 8765

# 单次工具调用上限改为 10 分钟（默认 5 分钟），并记录每次调用
python -m ida_auto_mcp --timeout 600 --trace C:/temp/ida-auto-mcp.jsonl

# 文件加载完 open_binary 就返回，IDA 在后台分析
python -m ida_auto_mcp --analysis-wait 0

# 详细日志
python -m ida_auto_mcp -v
```

### 权限

默认只提供读取数据库的工具，其余工具需要用参数开启：

| 参数 | 开启的工具 |
|------|------------|
| `--allow-write` | 修改 IDA 数据库或将其保存到磁盘的工具：`save_database`、`rename_address`、`set_comment`、`append_comment`、`set_function_type`、`declare_type`、`apply_type`、`enum_upsert`、`infer_types`、`declare_stack_var`、`delete_stack_var`、`define_function`、`define_code`、`undefine_code`、`patch_bytes`、`patch_asm` |
| `--allow-script` | `run_script`，以服务器进程的权限执行任意 Python 代码 |

在 MCP 客户端配置的 `args` 中加上这些参数即可，例如 `"args": ["-m", "ida_auto_mcp", "--allow-write"]`。未开启的工具不会出现在工具列表中，调用时会返回错误并提示所需的参数。与 IDA 平常的行为一样，打开二进制文件时仍会在文件旁边生成数据库文件，关闭或切换会话时也会保存这些文件。

分析不可信样本时请保持这两个参数关闭：二进制中的字符串和名称可能藏有针对 AI 智能体的提示注入内容。

每个工具还带有 MCP 标注：只读工具标记为 `readOnlyHint`，写入类工具和 `run_script` 标记为 `destructiveHint`，客户端可以据此区分它们。

### 后台分析

大型或经过混淆的程序，IDA 的自动分析可能要跑几个小时，而 idalib 自带的等待无法中断。因此服务器把分析拆成很小的步骤来执行。`open_binary` 最多等待分析 `--analysis-wait` 秒（默认 30；`0` 表示文件加载完就返回）。此后只要没有请求在等，服务器就以约 50 毫秒为一片继续推进分析，请求会在两片之间得到处理。个别步骤要花几秒，这时下一个请求要等它结束。

分析完成之前，函数列表、交叉引用和伪代码可能不完整，并会随分析推进而变化。`open_binary` 和 `get_database_info` 会返回 `analysis`：是否已完成（`complete`）、当前阶段（`stage`）和地址（`address`），以及目前找到的函数数（`functions`）。会话信息里的 `analysis` 为 `running`（进行中）、`paused`（其他会话处于活跃状态，切回本会话后继续）、`off`（未开启）或 `complete`（已完成）。`wait_analysis(timeout)` 最多等待 `timeout` 秒（默认 60，`0` 表示等到分析结束）并报告进度，可以取消。传入 `auto_analysis=false` 时不做任何分析，直到调用 `wait_analysis`。切换会话时，尚未完成的分析会随数据库一起保存。

由分析得出的结果会跟着分析更新：分析改动了数据库之后，函数会重新反编译，而不是沿用反编译器的缓存。`list_strings` 和 `search_strings` 会在多次调用之间复用 IDA 的字符串表，因为构建它要扫描整个数据库；分析进行期间最多每分钟重建一次，分析结束时再重建一次。

### 超时与取消

单次工具调用最多运行 `--timeout` 秒（默认 300，`0` 表示不限制）。超时后服务器会停止该调用，并返回错误，提示缩小请求范围。客户端通过 stdio 取消调用时（`notifications/cancelled`，例如你中断了智能体），服务器同样会停止它，且不再返回结果。Python 代码会立即停下；正在执行某个 IDA 函数的调用，要等该函数返回后才停下。在 IDA 9.5 及以上版本中，反编译器也会使用同一上限并自行中止。`wait_analysis` 会在两个分析步骤之间停下，并在到达上限前稍早结束，以便返回进度。打开、切换、关闭、保存数据库永远不会被中断，因此不会出现数据库只打开或保存了一半的情况。

`--trace FILE` 会为每次工具调用追加一行 JSON（工具、参数、耗时、错误），便于查看智能体做了什么、时间花在哪里。

### 打开数据库

打开数据库之前，服务器会先检查它的文件。如果另一个 IDA 实例（例如 IDA 界面）正打开着它，`open_binary` 会给出明确的错误并拒绝打开，当前会话保持不变。如果上次 IDA 没有正常关闭它（例如崩溃），IDA 会静默地重新打开上次保存的副本并丢弃留下的文件；服务器会先把这些文件复制到 `<名称>.i64.crash-<时间>/`，并在 `open_binary` 的结果中说明。

对于原始固件等 IDA 无法识别的文件，`open_binary` 支持加载选项：`processor`（例如 `arm`）、`file_type`（例如 `Binary file`）、`base_address` 和 `entry_point`。它们只在 IDA 为该文件新建数据库时生效，数据库已存在时会被忽略。

### 工具列表（共 55 个）

标注 *（写入）* 的工具需要 `--allow-write`；标注 *（脚本）* 的需要 `--allow-script`。

#### 会话管理
| 工具 | 说明 |
|------|------|
| `open_binary` | 打开二进制文件进行分析（最多等待自动分析 `--analysis-wait` 秒，之后在后台继续；原始固件可指定加载选项） |
| `close_binary` | 关闭分析会话 |
| `switch_binary` | 切换到其他会话 |
| `list_sessions` | 列出所有打开的会话 |
| `get_current_session` | 获取当前活跃会话信息 |

#### 数据库操作
| 工具 | 说明 |
|------|------|
| `get_database_info` | 获取二进制文件元数据（文件名、架构、基址、MD5、SHA256、文件大小） |
| `wait_analysis` | 推进自动分析，直到完成或超时，并报告进度 |
| `save_database` | 保存 IDA 数据库到磁盘 *（写入）* |

#### 分析功能
| 工具 | 说明 |
|------|------|
| `list_functions` | 列出/过滤函数（支持分页） |
| `get_function_info` | 获取函数详细信息（原型、大小） |
| `decompile_function` | Hex-Rays 反编译为 C 伪代码 |
| `disassemble_function` | 反汇编 |
| `get_xrefs_to` | 获取到某地址的交叉引用 |
| `get_xrefs_from` | 获取从某地址出发的交叉引用 |
| `export_function` | 导出函数为 C 头文件或完整反编译代码 |

#### 数据查询
| 工具 | 说明 |
|------|------|
| `list_strings` | 列出二进制中的字符串；IDA 9.5 中仅存在于代码里的合成字符串会标记为 `synthetic` |
| `search_strings` | 正则搜索字符串 |
| `list_imports` | 列出导入函数（按模块） |
| `list_exports` | 列出导出符号 |
| `list_segments` | 列出内存段/节 |
| `list_entrypoints` | 列出二进制入口点 |
| `get_globals` | 列出全局变量 |

#### 控制流分析
| 工具 | 说明 |
|------|------|
| `get_callers` | 查找调用指定函数的所有函数 |
| `get_callees` | 查找指定函数调用的所有函数 |
| `get_callgraph` | 构建调用图（BFS，支持深度控制） |
| `get_basic_blocks` | 获取函数基本块（含块类型/后继/前驱） |
| `get_address_info` | 解析地址所属的段/函数/符号 |
| `find_paths` | 在函数内查找两个地址间的控制流路径 |
| `trace_data_flow` | 沿交叉引用 BFS 追踪数据流（前向/后向） |

#### 类型与结构体
| 工具 | 说明 |
|------|------|
| `list_structs` | 列出数据库中的结构体/联合体 |
| `get_struct_info` | 获取结构体详细信息（含所有字段） |
| `list_local_types` | 列出所有本地类型（结构体、枚举、typedef）|
| `type_inspect` | 按名称查看类型详情（大小/类型/声明/成员） |
| `declare_type` | 声明 C 类型定义到本地类型库 *（写入）* |
| `apply_type` | 将类型应用到地址（函数、全局变量等） *（写入）* |
| `enum_upsert` | 创建或扩展枚举类型，可选位掩码枚举（幂等操作） *（写入）* |
| `infer_types` | 自动推断并应用地址处的类型（Hex-Rays/启发式） *（写入）* |
| `xrefs_to_field` | 获取结构体特定字段的交叉引用 |
| `get_stack_frame` | 获取函数栈帧布局；每个成员的 `fp_offset`（相对帧指针的偏移）就是栈变量工具使用的偏移 |
| `declare_stack_var` | 在指定 `fp_offset` 处创建或重命名栈变量 *（写入）* |
| `delete_stack_var` | 删除函数栈帧中指定 `fp_offset` 处的栈变量 *（写入）* |

#### 代码定义
| 工具 | 说明 |
|------|------|
| `define_function` | 在指定地址定义函数 *（写入）* |
| `define_code` | 将字节转换为代码指令 *（写入）* |
| `undefine_code` | 取消定义，恢复为原始字节 *（写入）* |

#### 搜索
| 工具 | 说明 |
|------|------|
| `search_bytes` | 字节模式搜索（支持通配符，如 `48 89 5C ?? 57`） |
| `find_insns` | 按助记符/操作数模式搜索指令（支持正则） |

#### 修改
| 工具 | 说明 |
|------|------|
| `rename_address` | 重命名函数/地址（自动刷新反编译缓存） *（写入）* |
| `set_comment` | 设置反汇编注释 *（写入）* |
| `append_comment` | 追加注释（不覆盖已有注释，自动去重） *（写入）* |
| `set_function_type` | 设置函数原型（自动刷新反编译缓存） *（写入）* |
| `patch_bytes` | 在指定地址写入字节（二进制补丁） *（写入）* |
| `patch_asm` | 汇编指令并写入到指定地址 *（写入）* |

#### 内存读取
| 工具 | 说明 |
|------|------|
| `read_bytes` | 读取指定地址的原始字节 |
| `get_string_at` | 读取指定地址的以 null 结尾的字符串 |

#### 脚本
| 工具 | 说明 |
|------|------|
| `run_script` | 执行 IDAPython 脚本；变量在多次调用间保留（直到打开其他数据库），并返回最后一个表达式的值 *（脚本）* |

### 多文件分析示例

```
用户：分析 main.exe 和它的 plugin.dll

AI: open_binary("C:/samples/main.exe")        → 打开并分析 main.exe
AI: list_functions(filter_str="*LoadPlugin*")  → 查找 LoadPlugin 函数
AI: decompile_function("LoadPlugin")           → 反编译
AI: open_binary("C:/samples/plugin.dll")       → 打开 plugin.dll（新会话）
AI: list_exports()                             → 查看 DLL 导出
AI: decompile_function("PluginInit")           → 反编译导出函数
AI: switch_binary("<main.exe 的会话 ID>")      → 切回 main.exe
AI: get_xrefs_to("0x401000")                  → 查看交叉引用
```

### 项目结构

```
ida_auto_mcp/
├── server.py        # 命令行入口，idapro 初始化
├── mcp_server.py    # MCP 协议实现（stdio + HTTP 传输）、超时控制
├── _registry.py     # 全局 McpServer 实例 + 工具装饰器
├── session.py       # 多文件会话管理（基于 idalib）
├── analysis.py      # 把 IDA 自动分析拆成有限的步骤执行
├── idb_files.py     # IDA 打开数据库前检查其文件
└── tools.py         # 55 个 IDA 分析工具
```

测试不需要安装 IDA，覆盖工具权限、HTTP 检查、协议层（版本协商、标注、超时、取消、调用记录、后台任务）、`run_script`、数据库文件检查和加载选项，并用 IDA 模块的替身测试分析步骤、随之刷新的缓存以及拆成多块的函数：

```bash
python -m unittest discover -s tests -v
```

`tests/tool_metadata.json` 是服务器向客户端公布的元数据快照。有意修改工具的名称、说明或参数后，运行 `IDA_AUTO_MCP_UPDATE_SNAPSHOT=1 python -m unittest tests.test_tool_metadata` 重新生成。GitHub Actions 会在 Windows 和 Linux 上运行这些测试。在 PyPI 上把本仓库配置为可信发布者（环境名 `pypi`）后，发布 GitHub Release 时会自动构建并上传到 PyPI。

### 安全

- **HTTP 传输**仅用于本机调试。它监听 127.0.0.1，每个发往 `/mcp` 的 POST 请求都必须带 `Authorization: Bearer <令牌>`。启动时会打印一个随机令牌；在客户端中注册服务器时，请改用环境变量 `IDA_AUTO_MCP_TOKEN` 指定固定令牌，因为随机令牌每次启动都会变。`Host` 或 `Origin` 不是本机回环地址的请求会被拒绝，以防御 DNS 重绑定和其他网站页面发起的请求。`--host` 会改变这一规则：绑定到某个具体地址时，该地址也会被接受为 `Host` 和 `Origin`；绑定到所有网卡（`0.0.0.0`）时，接受任意 `Host`，只靠令牌把关。这两种情况都会打印警告，因为流量没有加密。以 Claude Code 为例：`claude mcp add --transport http ida http://127.0.0.1:8765/mcp --header "Authorization: Bearer <令牌>"`。
- **不可信样本**：恶意软件只在隔离的虚拟机中分析。工具从样本中返回的一切内容（字符串、名称、反编译代码）对 AI 智能体来说都是不可信输入。
- **用途**：分析你拥有或获得授权分析的软件，例如恶意样本分析、漏洞研究、审计自己构建的程序和固件。请勿用于绕过软件授权。
- 发现漏洞请按 [SECURITY.md](https://github.com/mufeng05/ida-auto-mcp/blob/master/SECURITY.md) 中的方式报告。

### 致谢

- MCP 协议层（`mcp_server.py`）改编自 Duncan Ogilvie 的 [zeromcp](https://github.com/mrexodia/zeromcp)（MIT 许可证），详见 [THIRD_PARTY_NOTICES.md](https://github.com/mufeng05/ida-auto-mcp/blob/master/THIRD_PARTY_NOTICES.md)。
- 许多工具的命名和功能参考了 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。
- 控制流、结构体和补丁类工具最初参考 [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) 实现。
- 数据库文件检查和工具调用的中断方式参考了 Hex-Rays 的 [ida-nexus](https://github.com/HexRaysSA/ida-nexus)（MIT 许可证），它是官方 [IDA MCP 服务器](https://github.com/HexRaysSA/ida-mcp) 的底层库。

### 许可

MIT，详见 [LICENSE](https://github.com/mufeng05/ida-auto-mcp/blob/master/LICENSE)。IDA Pro 本身需要有效的许可证。
