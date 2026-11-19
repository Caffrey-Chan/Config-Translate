# H3C → FortiGate 配置转换器

使用 Python 3.10 或更新版本，无第三方依赖。输入 H3C Comware 7 配置文本，输出 FortiOS CLI 草稿和 JSON 迁移报告。CLI 以 FortiOS 7.4 的 IPv4、profile-based 防火墙策略模式为参考。当前仅做离线转换。

## 网页界面

在项目目录启动本地转换器。

```bash
python3 web_app.py
```

在同一台电脑的浏览器打开 `http://127.0.0.1:8765/`。端口已被使用时，可以用 `python3 web_app.py --port 8766` 启动并打开终端显示的地址。

1. 选择 H3C 配置文件（最多 16 MiB）。页面优先显示静态路由使用的接口，也可展开其余接口。
2. 在每个所需的源接口旁填写目标 FortiGate 接口名。要同时生成安全策略草稿，可展开「安全区域映射」并填写目标区域名。
3. 点击「生成转换草稿」，查看生成数量并下载 `fortigate.cli` 和 `migration.json`。缺少映射的路由和策略会列入报告；改动映射后可以重新转换。

程序监听本机回环地址。配置文件和填写的映射在本机内存中处理，下载由浏览器发起。

## 命令行

```bash
python3 translate.py "/path/to/startup.cfg" --cli fortigate.cli --report migration.json
```

没有目标映射时，只生成地址及服务对象，接口、区域、路由、安全策略与 NAT 的解析结果可在 JSON 中查看。要生成路由和安全策略草稿，可以提供已有的目标对象名，例如：

```json
{
  "interfaces": {
    "Route-Aggregation2": "agg-idc"
  },
  "zones": {
    "Untrust": "zone-idc",
    "TYC": "zone-tyc"
  }
}
```

```bash
python3 translate.py "/path/to/startup.cfg" --mapping mapping.json \
  --cli fortigate-mapped.cli --report migration-mapped.json \
  --route-start 10000 --policy-start 10000
```

映射值写目标 VDOM 中真实存在的三层出接口及已搭建的 FortiGate 区域。确认目标区域的成员、VLAN 及区内转发设置能表达源区域的匹配范围。可以提供部分映射，依赖缺失的条目会保留在报告中。接口及区域的映射各自要求一对一。

转换器优先尝试 UTF-8 和 GB18030，必要时逐行检测两种编码。可以用 `--encoding` 指定编码。输出路径必须是新文件。

## 转换范围

| 配置 | 程序行为 |
| --- | --- |
| IPv4 地址对象 | 支持主机、子网、范围，多成员组拆成地址对象和地址组。源地址组的区域绑定记录在报告中，引用该对象的策略必须限定到同一个源区域。 |
| 服务 | 支持已定义的 TCP/UDP 目的端口、端口范围及组合。 |
| 静态路由 | 支持 IPv4 网关路由及显式出口。缺少显式出口时，在已知直连子网中取唯一最长匹配。保留源 preference 数值为目标 distance。递归下一跳、歧义或缺少映射的条目进入人工复核。 |
| IPv4 安全策略 | 支持显式源和目的区域、已定义的地址和服务、常见字面 IPv4 地址条件、放行、拒绝与日志。按文件顺序生成，保留原始 ID 和启停状态于报告。涉及 Local、隐式任意区域或不支持条件的整条规则进入人工复核。 |
| NAT | 按原顺序记录 DNAT 目标、端口、源/目的限制和 SNAT 地址池、启停状态。目标的 NAT 模式、VIP 匹配顺序与策略关联需要单独复核。 |
| 拓扑及其他 | 盘点接口、聚合成员、区域和 VLAN 限定，同时统计 ACL、QoS 及其他未转换段落。管理员及认证段的正文不会写进输出。 |

路由和策略草稿统一以 `set status disable` 生成，地址和服务对象可被引用。导入前请核对目标版本、VDOM、对象名称、路由/策略 ID 是否空闲，以及策略在目标规则表中的位置。报告中的 `cli_disabled` 表示已生成停用草稿，`manual` 表示需要处理，`nat_review` 表示已解析出 NAT 复核项。结果含内部地址和网络拓扑，按源配置同样管理。

## 验证

用 `python3 -m unittest -v` 运行回归检查。CLI 语法参考了 FortiOS 7.4 文档，实际设备导入待验证。

- [FortiOS 7.4 静态路由 CLI](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/522620/config-router-static)
- [FortiOS 7.4 防火墙策略 CLI](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/292620/config-firewall-policy)
- [FortiOS 7.4 自定义服务 CLI](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/236620/config-firewall-service-custom)
- [H3C Comware 7 静态路由命令](https://www.h3c.com/en/Support/Resource_Center/EN/Home/Routers/00-Public/Reference_Guides/Command_References/H3C_MSR_Comware_7_CR-R0615/08/202210/1709603_294551_0.htm)
