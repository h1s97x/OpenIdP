# GeoIP 数据说明

本目录内嵌了两套离线 IP 地理数据库，解析顺序见 `geolocation.go`。

## GeoCN.mmdb（中国大陆高精度）

- 来源：[ljxi/GeoCN](https://github.com/ljxi/GeoCN) 项目 release 提供的 `GeoCN.mmdb`
- 覆盖：中国大陆 IPv4 + IPv6，部分 IP 精确到区县
- 结构：`division_code`（行政区划代码）+ `isp`（运营商）+ `type`
- 行政区划名称映射来自项目内 `full.txt`
- 数据随 [ljxi/GeoCN](https://github.com/ljxi/GeoCN) 不定期更新，可自行替换本目录 `GeoCN.mmdb` 后重新构建
- 许可证：参考上游项目声明

## ip2region.xdb（境外兜底）

- 项目主页：https://github.com/lionsoul2014/ip2region
- 数据版本：ip2region v4
- 许可证：Apache License 2.0
- 用途：GeoCN 未命中的境外 IP / 非大陆段解析

两者均通过 `//go:embed` 内嵌进 Go 二进制，无需外部依赖。

## 外部 API 源（可选）

设置环境变量 `GEO_API_SOURCES` 可启用外部 API 解析（GeoCN / ip2region 均未命中时按顺序尝试）：

- `ip-api.com`（免费，45 次/分，中文结果）
- `ipinfo.io`（免费档）
- `ipapi.co`（免费档，限流）
- `ip.sb`（公共接口）

结果带 24h 内存缓存（`GEO_API_CACHE_TTL` 可调）。
