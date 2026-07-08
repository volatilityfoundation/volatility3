---
tool_name: volatility3
mcp_server: volatility3.mcp.server
version: 1.0
author: AI Assistant
created: 2026-07-08
updated: 2026-07-08
tags: [memory-forensics, incident-response, rootkit-detection, malware-analysis]
---

# Volatility3 MCP Skill

## 概述

Volatility3 是先进的内存取证框架，用于分析内存转储以发现恶意活动。通过 MCP Server，AI Agent 可以自动化内存分析、进程检测、Rootkit 发现和 YARA 扫描。

### 主要功能

- **内存镜像加载**: 加载各种格式的内存转储
- **进程列表**: 列出运行中的进程
- **模块分析**: 列出加载的模块和驱动
- **Rootkit 检测**: 扫描隐藏的进程和模块
- **YARA 扫描**: 使用规则扫描内存
- **网络连接**: 分析网络连接
- **注册表分析**: 提取注册表配置单元

### 适用场景

- 事件响应和取证分析
- Rootkit 和恶意软件检测
- 内存中的证据提取
- 系统行为分析
- 安全事件调查

## 工具选择指南

### 何时使用 Volatility3

- 需要分析系统内存转储
- 需要检测隐藏的恶意进程
- 需要提取内存中的证据
- 需要进行 YARA 规则扫描
- 需要分析系统运行时的状态

### 与其他工具的对比

| 工具 | 类型 | 优势 | 劣势 |
|------|------|------|------|
| Volatility3 | 内存取证 | 全面的插件生态 | 需要内存转储 |
| pwndbg | 动态调试 | 实时分析 | 需要运行环境 |
| Frida | 动态插桩 | 实时Hook | 需要目标运行 |
| radare2 | 逆向工程 | 多平台支持 | 学习曲线陡峭 |

### 典型使用场景

1. **Rootkit 检测**: 发现隐藏的进程和模块
2. **恶意软件分析**: 提取内存中的恶意代码
3. **事件响应**: 分析受感染系统的内存
4. **证据提取**: 从内存中提取密码、密钥等

## 支持的工具

### 核心工具

- `load_memory_image` - 加载内存镜像
- `list_processes` - 列出进程
- `list_modules` - 列出模块
- `scan_for_rootkits` - Rootkit 扫描
- `yara_scan` - YARA 扫描
- `get_network_connections` - 网络连接
- `dump_process` - 转储进程
- `extract_registry` - 提取注册表

## 参数最佳实践

### load_memory_image

```python
# 推荐：指定操作系统类型
result = load_memory_image(
    image_path="/path/to/memory.raw",
    os_type="windows"  # 或 "linux", "mac"
)

# 对于大型镜像，使用延迟加载
result = load_memory_image(
    image_path="/path/to/large_memory.raw",
    os_type="windows",
    lazy_load=True
)
```

### list_processes

```python
# 推荐：使用 PID 过滤器
result = list_processes(
    os_type="windows",
    pid_filter=[1234, 5678]  # 只列出特定进程
)

# 列出所有进程
result = list_processes(os_type="windows")
```

### yara_scan

```python
# 推荐：指定扫描范围
result = yara_scan(
    os_type="windows",
    pid_filter=[1234],  # 只扫描特定进程
    rules_path="/path/to/rules.yar"
)

# 扫描所有进程
result = yara_scan(
    os_type="windows",
    rules_path="/path/to/rules.yar"
)
```

## 错误处理

参考 [MCP_ERROR_HANDLING.md](../MCP_ERROR_HANDLING.md) 中的错误码定义。

### 取证错误 (5000-5999)

| 错误码 | 名称 | 解决方案 |
|--------|------|----------|
| 5001 | IMAGE_LOAD_FAILED | 检查镜像文件格式和完整性 |
| 5002 | INVALID_IMAGE_FORMAT | 确认是支持的格式（raw, vmem, vmdk） |
| 5003 | PLUGIN_FAILED | 检查插件依赖和参数 |
| 5004 | YARA_SCAN_FAILED | 验证 YARA 规则语法 |
| 5005 | PROCESS_LIST_FAILED | 确认操作系统类型正确 |

### 常见错误及解决方案

**错误 1: 镜像加载失败**
```
Error: IMAGE_LOAD_FAILED - Cannot load memory image
```
解决方案：
- 检查镜像文件格式是否支持
- 验证文件完整性
- 确认操作系统类型正确

**错误 2: 进程列表为空**
```
Error: PROCESS_LIST_FAILED - No processes found
```
解决方案：
- 检查操作系统类型是否正确
- 验证镜像包含进程信息
- 尝试不同的配置文件

## Workflow 示例

### 基础工作流：Rootkit 检测

```python
async def detect_rootkits(image_path):
    # 1. 加载内存镜像
    await load_memory_image(
        image_path=image_path,
        os_type="windows"
    )
    
    # 2. 列出所有进程
    processes = await list_processes(os_type="windows")
    print(f"Found {len(processes['processes'])} processes")
    
    # 3. 扫描 Rootkit
    rootkits = await scan_for_rootkits(os_type="windows")
    
    if rootkits["findings"]:
        print("Rootkit detected!")
        for finding in rootkits["findings"]:
            print(f"  Type: {finding['type']}")
            print(f"  Details: {finding['details']}")
    else:
        print("No rootkit detected")
```

### 高级工作流：恶意软件分析

```python
async def analyze_malware(image_path, yara_rules):
    # 1. 加载镜像
    await load_memory_image(
        image_path=image_path,
        os_type="windows"
    )
    
    # 2. 列出可疑进程
    processes = await list_processes(os_type="windows")
    suspicious = [p for p in processes["processes"] 
                 if "malware" in p["name"].lower()]
    
    # 3. 对可疑进程进行 YARA 扫描
    for proc in suspicious:
        scan_result = await yara_scan(
            os_type="windows",
            pid_filter=[proc["pid"]],
            rules_path=yara_rules
        )
        
        if scan_result["matches"]:
            print(f"Malware detected in {proc['name']}!")
            for match in scan_result["matches"]:
                print(f"  Rule: {match['rule']}")
    
    # 4. 转储恶意进程
    for proc in suspicious:
        dump = await dump_process(
            os_type="windows",
            pid=proc["pid"],
            output_path=f"/tmp/{proc['name']}.dmp"
        )
        print(f"Dumped {proc['name']} to {dump['path']}")
```

## Prompt 模板

### 基础调用模板

```python
# 调用 Volatility3 MCP 工具
async def analyze_memory():
    result = await mcp_client.call_tool(
        tool_name="list_processes",
        arguments={"os_type": "windows"}
    )
    
    if result["status"] == "success":
        processes = result["data"]["processes"]
        print(f"Found {len(processes)} processes")
    else:
        print(f"Error: {result['error_message']}")
```

### 自动化脚本模板

```python
#!/usr/bin/env python3
"""
Volatility3 MCP 自动化分析脚本
"""
import asyncio
from mcp import Client

async def main():
    async with Client("volatility3") as client:
        # 加载镜像
        await client.call_tool("load_memory_image", {
            "image_path": "memory.raw",
            "os_type": "windows"
        })
        
        # 列出进程
        processes = await client.call_tool("list_processes", {
            "os_type": "windows"
        })
        
        print(f"Found {len(processes['data']['processes'])} processes")
        
        # Rootkit 扫描
        rootkits = await client.call_tool("scan_for_rootkits", {
            "os_type": "windows"
        })
        
        if rootkits["data"]["findings"]:
            print("Rootkit detected!")

if __name__ == "__main__":
    asyncio.run(main())
```

## 最佳实践

### 性能优化建议

1. **使用 PID 过滤器**
   - 只分析感兴趣的进程
   - 减少不必要的扫描

2. **延迟加载**
   - 对大型镜像使用延迟加载
   - 按需加载分析结果

3. **缓存结果**
   - 缓存进程列表
   - 避免重复扫描

### 安全注意事项

1. **隔离环境**
   - 在隔离环境中分析恶意内存
   - 避免在主机上直接分析

2. **数据保护**
   - 内存镜像可能包含敏感信息
   - 安全存储分析结果

3. **结果验证**
   - 交叉验证多个工具的结果
   - 不要完全依赖自动化分析

### 常见问题解答

**Q: 如何确定操作系统类型？**
A: 使用 `load_memory_image` 的自动检测功能，或检查镜像来源信息。

**Q: 如何处理大型内存镜像？**
A: 使用延迟加载，只分析感兴趣的进程，使用 PID 过滤器。

**Q: 如何编写 YARA 规则？**
A: 参考 YARA 文档，使用字符串匹配、正则表达式和条件语句。

**Q: 如何分析 Linux 内存？**
A: 设置 `os_type="linux"`，使用 Linux 特定的插件。

---

**相关资源**
- [Volatility3 项目](https://github.com/volatilityfoundation/volatility3)
- [MCP 协议](https://modelcontextprotocol.io/)
- [错误处理规范](../MCP_ERROR_HANDLING.md)
