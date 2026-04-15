# IDA Auto MCP

[English](#english) | [中文](#中文)

---

## English

Headless IDA Pro MCP server that enables AI agents to **automatically** open, analyze, and query multiple binary files — no manual IDA GUI interaction required.

### Why This Project?

Existing IDA MCP solutions (like [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)) require you to:
1. Manually open IDA Pro GUI
2. Manually activate the MCP plugin (Ctrl+Alt+M)
3. Repeat for every binary you want to analyze

This makes multi-file analysis (e.g., a program with multiple DLLs) painful. **IDA Auto MCP** solves this by using IDA's headless `idalib` library, letting AI agents autonomously open and analyze any number of binaries.

### Key Features

- **Fully Automatic** — AI agents call `open_binary("path/to/file.dll")` to start analysis, no human in the loop
- **Multi-Binary Sessions** — Open multiple binaries simultaneously, switch between them freely
- **Headless** — Uses `idalib` (IDA as a library), no GUI needed
- **63 Analysis Tools** — Decompile, disassemble, xrefs, strings, imports, types, search, rename, patching, and more
- **MCP Standard** — Works with Claude Desktop, Claude Code, and any MCP-compatible client
- **Stdio + HTTP** — Stdio transport for MCP clients, HTTP for debugging

### Prerequisites

1. **IDA Pro 9.0+** (with valid license)
2. **idapro Python package** — shipped with IDA Pro:
   ```bash
   pip install "<IDA_INSTALL_DIR>/idalib/python/idapro-9.0-py3-none-win_amd64.whl"
   ```
3. **IDADIR** — set via environment variable or `--ida-dir` flag

### Installation

```bash
git clone https://github.com/mufeng05/ida-auto-mcp.git
cd ida-auto-mcp
pip install -e .
```

### Quick Start

#### Claude Code (`~/.claude.json`)

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
# Start server (stdio mode, default)
python -m ida_auto_mcp

# Pre-load a binary on startup
python -m ida_auto_mcp C:/samples/target.exe

# HTTP mode for debugging
python -m ida_auto_mcp --transport http --port 8765

# Verbose logging
python -m ida_auto_mcp -v
```

### Tools (63 total)

#### Session Management
| Tool | Description |
|------|-------------|
| `open_binary` | Open a binary for analysis (auto-analysis included) |
| `close_binary` | Close a session |
| `switch_binary` | Switch active session |
| `list_sessions` | List all open sessions |
| `get_current_session` | Get active session info |

#### Database
| Tool | Description |
|------|-------------|
| `get_database_info` | Binary metadata (filename, arch, imagebase, MD5, SHA256, file size) |
| `wait_analysis` | Wait for auto-analysis to complete |
| `save_database` | Save IDA database to disk |

#### Analysis
| Tool | Description |
|------|-------------|
| `list_functions` | List/filter functions with pagination |
| `get_function_info` | Detailed function info (prototype, size) |
| `decompile_function` | Hex-Rays decompilation to C pseudocode |
| `disassemble_function` | Assembly disassembly |
| `get_xrefs_to` | Cross-references TO an address |
| `get_xrefs_from` | Cross-references FROM an address |

#### Data
| Tool | Description |
|------|-------------|
| `list_strings` | Strings in the binary |
| `search_strings` | Regex search in strings |
| `list_imports` | Imported functions by module |
| `list_exports` | Exported symbols |
| `list_segments` | Memory segments/sections |

#### Control Flow
| Tool | Description |
|------|-------------|
| `get_callers` | Find all functions that call a given function |
| `get_callees` | Find all functions called by a given function |
| `get_callgraph` | Build call graph with depth control (BFS) |
| `get_basic_blocks` | Get CFG basic blocks with type/successor/predecessor info |
| `get_address_info` | Resolve address to segment/function/symbol context |
| `find_paths` | Find control-flow paths between two addresses in the same function |
| `xref_matrix` | Build cross-reference matrix between multiple addresses |
| `trace_data_flow` | BFS data flow tracing via xrefs (forward/backward) |

#### Composite Analysis
| Tool | Description |
|------|-------------|
| `survey_binary` | One-call binary triage (metadata, top functions/strings, import categories) |
| `analyze_function` | Comprehensive function analysis (pseudocode, strings, constants, callers, complexity) |

#### Types & Structs
| Tool | Description |
|------|-------------|
| `list_structs` | List structs/unions in the database |
| `get_struct_info` | Get struct details with all member fields |
| `list_local_types` | List all local types (structs, enums, typedefs) with filtering |
| `declare_type` | Declare C type definition in local type library |
| `apply_type` | Apply type to address (function, global, etc.) |
| `read_struct_at` | Read struct field values from memory at an address |
| `get_stack_frame` | Get stack frame layout (locals, args) |
| `declare_stack_var` | Create or rename a stack variable |
| `delete_stack_var` | Delete a stack variable from a function frame |
| `list_entrypoints` | List binary entry points |
| `get_globals` | List global variables |

#### Search
| Tool | Description |
|------|-------------|
| `search_bytes` | Byte pattern search with wildcards (`48 89 5C ?? 57`) |
| `find_insns` | Find instructions matching mnemonic/operand pattern (regex) |
| `find_immediate` | Search for immediate values in instructions |
| `xrefs_to_string` | Find strings matching query and return xrefs to each |
| `resolve_function` | Find functions by partial name match (fuzzy search) |

#### Code Definition
| Tool | Description |
|------|-------------|
| `define_function` | Define a function at an address |
| `define_code` | Convert bytes to code instructions |
| `undefine_code` | Undefine items back to raw bytes |

#### Modify
| Tool | Description |
|------|-------------|
| `rename_address` | Rename function/address |
| `set_comment` | Set disassembly comment |
| `set_function_type` | Set function prototype |
| `patch_bytes` | Patch bytes at an address (binary patching) |
| `patch_asm` | Assemble instruction and patch at address |
| `append_comment` | Append comment without overwriting (auto-dedup) |
| `read_bytes` | Read raw bytes at address |
| `get_string_at` | Read null-terminated string at address |
| `infer_types` | Auto-infer and apply type at address (Hex-Rays/heuristic) |
| `pseudocode_at` | Get decompiled pseudocode lines at a specific address |

#### Batch Operations
| Tool | Description |
|------|-------------|
| `batch_decompile` | Decompile multiple functions in one call |
| `batch_rename` | Rename multiple addresses in one call |

#### Utilities
| Tool | Description |
|------|-------------|
| `int_convert` | Convert numbers between decimal/hex/binary/ASCII |
| `export_function` | Export function as C header or full decompiled code |
| `run_script` | Execute arbitrary IDAPython code |

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
├── mcp_server.py    # MCP protocol implementation (stdio + HTTP)
├── _registry.py     # Global McpServer instance + @tool decorator
├── session.py       # Multi-binary session management via idalib
└── tools.py         # 63 IDA analysis tools
```

### License

This project is for personal and educational use. Requires a valid IDA Pro license.

---

## 中文

无界面 IDA Pro MCP 服务器，让 AI 智能体**自动**打开、分析和查询多个二进制文件——无需手动操作 IDA GUI。

### 为什么做这个项目？

现有的 IDA MCP 方案（如 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)）需要你：
1. 手动打开 IDA Pro 界面
2. 手动启用 MCP 插件（Ctrl+Alt+M）
3. 每分析一个文件都要重复上述步骤

这对于多文件分析（比如一个包含多个 DLL 的程序）非常不友好。**IDA Auto MCP** 使用 IDA 的无头分析库 `idalib`，让 AI 智能体能够自主打开和分析任意数量的二进制文件。

### 核心特性

- **全自动** — AI 直接调用 `open_binary("path/to/file.dll")` 即可开始分析，无需人工干预
- **多文件会话** — 同时打开多个二进制文件，自由切换
- **无需 GUI** — 使用 `idalib`（IDA 库模式），不需要打开 IDA 界面
- **63 个分析工具** — 反编译、反汇编、交叉引用、字符串、导入表、类型系统、搜索、重命名、补丁等
- **MCP 标准协议** — 支持 Claude Desktop、Claude Code 及所有 MCP 兼容客户端
- **双传输模式** — stdio 模式用于 MCP 客户端，HTTP 模式用于调试

### 前置要求

1. **IDA Pro 9.0+**（需要有效许可证）
2. **idapro Python 包** — IDA Pro 安装目录自带：
   ```bash
   pip install "<IDA安装目录>/idalib/python/idapro-9.0-py3-none-win_amd64.whl"
   ```
3. **IDADIR** — 通过环境变量或 `--ida-dir` 参数设置 IDA 安装路径

### 安装

```bash
git clone https://github.com/mufeng05/ida-auto-mcp.git
cd ida-auto-mcp
pip install -e .
```

### 快速开始

#### Claude Code 配置 (`~/.claude.json`)

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
# 启动服务器（stdio 模式，默认）
python -m ida_auto_mcp

# 启动时预加载一个文件
python -m ida_auto_mcp C:/samples/target.exe

# HTTP 模式（调试用）
python -m ida_auto_mcp --transport http --port 8765

# 详细日志
python -m ida_auto_mcp -v
```

### 工具列表（共 63 个）

#### 会话管理
| 工具 | 说明 |
|------|------|
| `open_binary` | 打开二进制文件进行分析（含自动分析） |
| `close_binary` | 关闭分析会话 |
| `switch_binary` | 切换到其他会话 |
| `list_sessions` | 列出所有打开的会话 |
| `get_current_session` | 获取当前活跃会话信息 |

#### 数据库操作
| 工具 | 说明 |
|------|------|
| `get_database_info` | 获取二进制文件元数据（文件名、架构、基址、MD5、SHA256、文件大小） |
| `wait_analysis` | 等待自动分析完成 |
| `save_database` | 保存 IDA 数据库到磁盘 |

#### 分析功能
| 工具 | 说明 |
|------|------|
| `list_functions` | 列出/过滤函数（支持分页） |
| `get_function_info` | 获取函数详细信息（原型、大小） |
| `decompile_function` | Hex-Rays 反编译为 C 伪代码 |
| `disassemble_function` | 反汇编 |
| `get_xrefs_to` | 获取到某地址的交叉引用 |
| `get_xrefs_from` | 获取从某地址出发的交叉引用 |

#### 数据查询
| 工具 | 说明 |
|------|------|
| `list_strings` | 列出二进制中的字符串 |
| `search_strings` | 正则搜索字符串 |
| `list_imports` | 列出导入函数（按模块） |
| `list_exports` | 列出导出符号 |
| `list_segments` | 列出内存段/节 |

#### 控制流分析
| 工具 | 说明 |
|------|------|
| `get_callers` | 查找调用指定函数的所有函数 |
| `get_callees` | 查找指定函数调用的所有函数 |
| `get_callgraph` | 构建调用图（BFS，支持深度控制） |
| `get_basic_blocks` | 获取函数基本块（含块类型/后继/前驱） |
| `get_address_info` | 解析地址所属的段/函数/符号 |
| `find_paths` | 在函数内查找两个地址间的控制流路径 |
| `xref_matrix` | 构建多地址间的交叉引用矩阵 |
| `trace_data_flow` | 沿交叉引用 BFS 追踪数据流（前向/后向） |

#### 综合分析
| 工具 | 说明 |
|------|------|
| `survey_binary` | 一次调用完成二进制分类（元数据、Top 函数/字符串、导入分类） |
| `analyze_function` | 函数综合分析（伪代码、字符串、常量、调用者、复杂度） |

#### 类型与结构体
| 工具 | 说明 |
|------|------|
| `list_structs` | 列出数据库中的结构体/联合体 |
| `get_struct_info` | 获取结构体详细信息（含所有字段） |
| `list_local_types` | 列出所有本地类型（结构体、枚举、typedef）|
| `declare_type` | 声明 C 类型定义到本地类型库 |
| `apply_type` | 将类型应用到地址（函数、全局变量等） |
| `read_struct_at` | 在内存地址读取结构体字段值 |
| `get_stack_frame` | 获取函数栈帧布局 |
| `declare_stack_var` | 创建或重命名栈变量 |
| `delete_stack_var` | 删除函数栈帧中的栈变量 |
| `list_entrypoints` | 列出二进制入口点 |
| `get_globals` | 列出全局变量 |

#### 搜索
| 工具 | 说明 |
|------|------|
| `search_bytes` | 字节模式搜索（支持通配符，如 `48 89 5C ?? 57`） |
| `find_insns` | 按助记符/操作数模式搜索指令（支持正则） |
| `find_immediate` | 搜索指令中的立即数值 |
| `xrefs_to_string` | 查找匹配字符串及其交叉引用 |
| `resolve_function` | 按名称模糊搜索函数 |

#### 代码定义
| 工具 | 说明 |
|------|------|
| `define_function` | 在指定地址定义函数 |
| `define_code` | 将字节转换为代码指令 |
| `undefine_code` | 取消定义，恢复为原始字节 |

#### 修改
| 工具 | 说明 |
|------|------|
| `rename_address` | 重命名函数/地址 |
| `set_comment` | 设置反汇编注释 |
| `set_function_type` | 设置函数原型 |
| `patch_bytes` | 在指定地址写入字节（二进制补丁） |
| `patch_asm` | 汇编指令并写入到指定地址 |
| `append_comment` | 追加注释（不覆盖已有注释，自动去重） |
| `read_bytes` | 读取指定地址的原始字节 |
| `get_string_at` | 读取指定地址的以 null 结尾的字符串 |
| `infer_types` | 自动推断并应用地址处的类型（Hex-Rays/启发式） |
| `pseudocode_at` | 获取特定地址处的反编译伪代码行 |

#### 批量操作
| 工具 | 说明 |
|------|------|
| `batch_decompile` | 一次调用反编译多个函数 |
| `batch_rename` | 一次调用重命名多个地址 |

#### 实用工具
| 工具 | 说明 |
|------|------|
| `int_convert` | 十进制/十六进制/二进制/ASCII 之间的数值转换 |
| `export_function` | 导出函数为 C 头文件或完整反编译代码 |
| `run_script` | 执行 IDAPython 脚本 |

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
├── mcp_server.py    # MCP 协议实现（stdio + HTTP 传输）
├── _registry.py     # 全局 McpServer 实例 + @tool 装饰器
├── session.py       # 多文件会话管理（基于 idalib）
└── tools.py         # 63 个 IDA 分析工具
```

### 许可

本项目供个人学习和研究使用，需要有效的 IDA Pro 许可证。
