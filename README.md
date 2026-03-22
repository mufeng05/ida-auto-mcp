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
- **25 Analysis Tools** — Decompile, disassemble, xrefs, strings, imports, search, rename, and more
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

### Tools (25 total)

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
| `get_database_info` | Binary metadata (filename, arch, imagebase) |
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

#### Search & Modify
| Tool | Description |
|------|-------------|
| `search_bytes` | Byte pattern search with wildcards (`48 89 5C ?? 57`) |
| `rename_address` | Rename function/address |
| `set_comment` | Set disassembly comment |
| `set_function_type` | Set function prototype |
| `read_bytes` | Read raw bytes at address |
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
└── tools.py         # 25 IDA analysis tools
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
- **25 个分析工具** — 反编译、反汇编、交叉引用、字符串、导入表、搜索、重命名等
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

### 工具列表（共 25 个）

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
| `get_database_info` | 获取二进制文件元数据（文件名、架构、基址） |
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

#### 搜索与修改
| 工具 | 说明 |
|------|------|
| `search_bytes` | 字节模式搜索（支持通配符，如 `48 89 5C ?? 57`） |
| `rename_address` | 重命名函数/地址 |
| `set_comment` | 设置反汇编注释 |
| `set_function_type` | 设置函数原型 |
| `read_bytes` | 读取指定地址的原始字节 |
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
└── tools.py         # 25 个 IDA 分析工具
```

### 许可

本项目供个人学习和研究使用，需要有效的 IDA Pro 许可证。
