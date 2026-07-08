# Volatility3 MCP Server

AI Agent 接口，用于通过 Model Context Protocol 访问 Volatility3 的内存取证功能。

## 功能特性

- **内存镜像加载**: 加载和分析内存镜像
- **进程列表**: 列出运行中的进程
- **模块分析**: 列出加载的模块和驱动
- **Rootkit 检测**: 扫描潜在的 Rootkit
- **YARA 扫描**: 使用 YARA 规则扫描内存
- **网络连接**: 分析网络连接
- **注册表分析**: 提取和分析注册表配置单元

## 工具列表

### 1. `load_memory_image`
加载内存镜像进行分析。

```python
result = load_memory_image(image_path="/path/to/memory.raw")
# 返回: {"image_path": "/path/to/memory.raw", "layers": [...], "status": "loaded"}
```

### 2. `list_processes`
列出运行中的进程。

```python
result = list_processes(os_type="windows")
# 返回: {"processes": [{"pid": 1234, "name": "process.exe", ...}, ...]}

# 使用 PID 过滤器
result = list_processes(os_type="windows", pid_filter=[1234, 5678])
```

### 3. `list_modules`
列出加载的模块。

```python
result = list_modules(os_type="windows")
# 返回: {"modules": [{"name": "ntoskrnl.exe", "base": 0xfffff80000000000, ...}, ...]}
```

### 4. `scan_for_rootkits`
扫描潜在的 Rootkit。

```python
result = scan_for_rootkits(os_type="windows")
# 返回: {"findings": [{"type": "hidden_process", "details": {...}}, ...]}
```

### 5. `yara_scan`
使用 YARA 规则扫描内存。

```python
result = yara_scan(yara_rule="rule test { strings: $a = \"malware\" condition: $a }")
# 返回: {"matches": [{"rule": "test", "address": 0x100000, "process": "malware.exe"}, ...]}
```

### 6. `list_network_connections`
列出网络连接。

```python
result = list_network_connections(os_type="windows", pid=1234)
# 返回: {"connections": [{"local_addr": "192.168.1.1:80", "remote_addr": "10.0.0.1:443", ...}, ...]}
```

### 7. `dump_process_memory`
转储进程内存。

```python
result = dump_process_memory(pid=1234, output_path="/tmp/dump.bin")
# 返回: {"status": "success", "dumped_size": 1024000, "output_path": "/tmp/dump.bin"}
```

### 8. `analyze_registry`
分析注册表配置单元。

```python
result = analyze_registry(os_type="windows", hive="SOFTWARE")
# 返回: {"keys": [{"path": "Microsoft\\Windows\\CurrentVersion", ...}, ...]}
```

## 安装

```bash
pip install volatility3 mcp
```

## 使用方法

### 作为独立服务器运行

```bash
python -m volatility3.mcp.server --stdio
```

### 传输方式

支持三种传输方式：

1. **stdio**（默认）:
   ```bash
   python -m volatility3.mcp.server --stdio
   ```

2. **SSE**:
   ```bash
   python -m volatility3.mcp.server --sse --host 127.0.0.1 --port 8000
   ```

3. **HTTP**:
   ```bash
   python -m volatility3.mcp.server --http --host 127.0.0.1 --port 8000
   ```

## AI Agent 集成示例

### Claude Desktop 配置

```json
{
  "mcpServers": {
    "volatility3": {
      "command": "python",
      "args": ["-m", "volatility3.mcp.server", "--stdio"]
    }
  }
}
```

### 使用示例

```python
from mcp import Client

async def analyze_memory():
    async with Client("volatility3") as client:
        # 加载内存镜像
        image = await client.call_tool("load_memory_image", {
            "image_path": "/path/to/memory.raw"
        })
        
        # 列出进程
        processes = await client.call_tool("list_processes", {
            "os_type": "windows"
        })
        for proc in processes["processes"]:
            print(f"PID {proc['pid']}: {proc['name']}")
        
        # 扫描 Rootkit
        findings = await client.call_tool("scan_for_rootkits", {
            "os_type": "windows"
        })
        if findings["findings"]:
            print(f"Found {len(findings['findings'])} suspicious items")
```

## 常见使用场景

### 1. 恶意软件分析

```python
# 1. 加载内存镜像
await client.call_tool("load_memory_image", {
    "image_path": "infected_memory.raw"
})

# 2. 列出所有进程
processes = await client.call_tool("list_processes", {
    "os_type": "windows"
})

# 3. 查找可疑进程
for proc in processes["processes"]:
    if "svchost" not in proc["name"].lower() and proc["pid"] > 1000:
        print(f"Suspicious: {proc['name']} (PID: {proc['pid']})")

# 4. 扫描恶意软件特征
yara_result = await client.call_tool("yara_scan", {
    "yara_rule": """
    rule malware_signature {
        strings:
            $a = {4D 5A 90 00 03 00 00 00}
        condition:
            $a
    }
    """
})
```

### 2. Rootkit 检测

```python
# 1. 加载内存镜像
await client.call_tool("load_memory_image", {
    "image_path": "compromised.raw"
})

# 2. 扫描 Rootkit
findings = await client.call_tool("scan_for_rootkits", {
    "os_type": "windows"
})

# 3. 分析发现
for finding in findings["findings"]:
    print(f"Type: {finding['type']}")
    print(f"Details: {finding['details']}")
```

### 3. 网络取证

```python
# 1. 列出网络连接
connections = await client.call_tool("list_network_connections", {
    "os_type": "windows",
    "pid": 1234
})

# 2. 分析可疑连接
for conn in connections["connections"]:
    if "443" in conn["remote_addr"] or "80" in conn["remote_addr"]:
        print(f"Connection: {conn['local_addr']} -> {conn['remote_addr']}")
```

## 测试

运行测试套件：

```bash
pytest volatility3/tests/test_mcp_tools.py -v
```

测试覆盖率：80%

## 错误处理

所有工具返回统一的错误格式：

```python
{
    "status": "error",
    "message": "Error description"
}
```

## 依赖项

- Python 3.8+
- volatility3
- mcp (Model Context Protocol SDK)

## 许可证

与 Volatility3 项目相同。

## 相关链接

- [Volatility3 项目](https://github.com/volatilityfoundation/volatility3)
- [Model Context Protocol](https://modelcontextprotocol.io/)
