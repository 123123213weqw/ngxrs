# nginx 兼容矩阵

图例：`✅` 已实现并测过 · `🟡` 部分实现/有已知差异 · `⬜` 未实现

对照基线：nginx 1.28.0（V100 `/usr/bin/nginx`）。

## core / 配置

| 能力 | 状态 | 备注 |
|---|---|---|
| nginx.conf 词法（注释、单双引号、转义、`${var}`） | ✅ | `src/config/lexer.rs` |
| 指令/块/`;` 语法与报错 | ✅ | 报错带 file:line |
| `include` + 通配符 | ✅ | 支持 `*` `?`，按路径排序 |
| 上下文继承（http → server → location） | 🟡 | 基础字段已继承；`add_header` 目前是累加而非"覆盖" |
| `-t` 配置自检 | ✅ | |
| `-s reload/stop`、daemon/fork 模型 | ⬜ | 当前前台单进程多线程 |
| `worker_processes N/auto` | ✅ | 每 worker 一线程 + 独立 runtime |
| 两种 accept 策略 | ✅ | `NGXRS_ACCEPT=reuseport`（默认）/ `shared`（单监听+轮询分发） |
| 未知指令处理 | 🟡 | 记 warning 继续；nginx 是直接报错 |

## http core

| 能力 | 状态 | 备注 |
|---|---|---|
| HTTP/1.0 / 1.1 解析 | ✅ | 请求行、header 名 token 校验、obs-fold 拒绝 |
| keepalive / pipelining | ✅ | 同一连接多请求；`keepalive_timeout` 生效 |
| Host 虚拟主机（精确/通配/正则） | ✅ | `server_name`，含 `*.x` / `.x` / `~re` |
| URI 规范化（合并斜杠、`.`/`..`） | ✅ | 越界 `..` → 400 |
| 百分号解码 | ✅ | 非法转义 / `%00` → 400 |
| 请求体丢弃 / `client_max_body_size` | ✅ | 超限 413；chunked 可丢弃 |
| `100-continue` | ✅ | |
| 请求行/头大小限制 | 🟡 | 8 KB 行 / 32 KB 头；nginx 是 `large_client_header_buffers` 4×8k |
| 访问日志（`log_format`、combined） | 🟡 | 变量替换已支持常用集合；转义尚未做 |
| 错误日志分级/落盘 | ⬜ | 仅 stderr |
| `server_tokens` | ✅ | on → `nginx/1.28.0`，off → `nginx` |

## http 静态内容

| 能力 | 状态 | 备注 |
|---|---|---|
| `root` / `alias` | ✅ | |
| `index` | ✅ | 多候选 |
| `autoindex` | 🟡 | 有列表页，样式/字段未逐字对齐 |
| ETag / Last-Modified / 304 | ✅ | ETag 格式与 nginx 一致（mtime-size 十六进制） |
| Range（单区间/后缀） | ✅ | 206 + Content-Range；多区间未做 |
| 416 | ✅ | `Content-Range: bytes */size` |
| 条件请求 If-Match / If-Unmodified-Since | ✅ | |
| `sendfile` | ✅ | Linux 走 `sendfile(2)`，非 Linux 回退 read+write |
| `tcp_nopush` / `tcp_nodelay` | 🟡 | 解析并接受，未细调 |
| `try_files` | 🟡 | 文件候选 + `=code`；内部重定向到 location 未做 |
| `return` | ✅ | 状态码 + 文本/URL |
| `add_header` | 🟡 | 累加语义（见上） |
| `error_page` | ⬜ | 已解析未生效 |
| 405 / 301 / 505 语义 | ✅ | 与 nginx 逐字节对齐（405 错误页、301 绝对 Location + body、505） |
| `expires` / `gzip` / `charset` | ⬜ | 已解析未生效 |

## 反向代理 / 上游

| 能力 | 状态 | 备注 |
|---|---|---|
| `proxy_pass http://host[:port][/uri]` | ✅ | URI 前缀替换、`$` 变量 |
| `upstream {}` + 多 server | ✅ | `weight` / `backup` / `down` 解析 |
| 负载均衡 rr / least_conn / ip_hash | ✅ | ip_hash 按 IPv4 前三段 |
| upstream `keepalive N` + 连接池 | ✅ | 池按 (upstream, server) 键，避免串后端 |
| `proxy_http_version` 1.0 / 1.1 | ✅ | |
| `proxy_set_header`（含 `$http_*`、`$remote_addr`、`$proxy_add_x_forwarded_for`） | ✅ | |
| WebSocket（101 + 双向管道） | ✅ | |
| 请求体转发（Content-Length / chunked 解块） | ✅ | |
| 响应体流式转发（定长 / chunked / 无长度） | ✅ | chunked 原样透传 |
| `proxy_connect_timeout` / `read_timeout` / `send_timeout` | ✅ | |
| `proxy_buffering` | 🟡 | 已解析；当前总是流式转发 |
| 上游失败重试（stale pooled socket） | 🟡 | 仅幂等方法重试同一后端 |
| `proxy_cache` / `proxy_cache_path`（levels/keys_zone/max_size/inactive） | ✅ | 磁盘缓存（原子替换写入），`X-Cache-Status` 走 `add_header $upstream_cache_status` |
| `proxy_cache_valid` / `proxy_cache_key` / `proxy_cache_bypass` | ✅ | 只缓存 `proxy_cache_valid` 列出的状态码 |
| 缓存淘汰（max_size / inactive） | 🟡 | max_size 按 mtime 淘汰；`inactive` 只解析未执行定时清理 |
| `proxy_no_cache` | 🟡 | 已解析，未按变量求值 |
| `fastcgi_pass` / `fastcgi_param` / `fastcgi_index` / `fastcgi_split_path_info` | ✅ | FastCGI 1.0 记录协议；`$fastcgi_script_name`、`$fastcgi_path_info` 等变量 |
| FastCGI 无 Content-Length 时用 chunked | ✅ | 与 nginx 帧格式逐字节一致 |
| `fastcgi_connect_timeout` / `fastcgi_read_timeout` | ✅ | |
| `fastcgi_cache` / `fastcgi_buffers` / `fastcgi_keep_conn` | ⬜ | 已解析未生效 |
| `uwsgi_pass` / `scgi_pass` / `grpc_pass` | ⬜ | |

## 内容过滤

| 能力 | 状态 | 备注 |
|---|---|---|
| `gzip on` | ✅ | Accept-Encoding 协商、q=0 拒绝 |
| `gzip_min_length` / `gzip_comp_level` / `gzip_types` / `gzip_vary` | ✅ | |
| 压缩结果缓存 | ✅ | 按 ETag+长度，每 worker 128 条上限 |
| 与 nginx 的差异 | 🟡 | nginx 流式压缩用 chunked，我们用 Content-Length；解码后内容一致 |
| `gunzip` / `gzip_static` / `brotli` | ⬜ | |
| `error_page`（含 `=code`、internal location、error_page 的 no-trigger 语义） | ✅ | 与 nginx 逐字节一致 |

## 安全 / 协议

| 能力 | 状态 | 备注 |
|---|---|---|
| `listen ... ssl` + `ssl_certificate` / `ssl_certificate_key` | ✅ | rustls（ring provider） |
| SNI 选证（精确名 / `*.通配` / 默认回落） | ✅ | 与 nginx 同序，通配只匹配一级标签 |
| TLS 1.2 / 1.3 | ✅ | 1.3 默认优先 |
| `ssl_protocols` / `ssl_ciphers` / `ssl_session_cache` 等 | 🟡 | 已解析；实际参数由 rustls 的安全默认值决定 |
| ALPN（h2 / http/1.1） | ✅ | 仅在 `listen ... http2` 时广告 h2 |
| HTTP/2（多路复用、`:authority` 选虚拟主机、头部规范化） | ✅ | 复用 http/1 的路由表，静态/return/error_page/gzip 行为一致 |
| HTTP/2 上的反向代理 | ⬜ | 目前 proxy 需要 socket 写入；h2 请求走 proxy 会返回 502 |
| HTTP/3 (QUIC) | ⬜ | 未开始 |
| `limit_req` / `limit_conn` / `access` 访问控制 | ⬜ | |

## rewrite

| 能力 | 状态 | 备注 |
|---|---|---|
| `rewrite <re> <replacement>;` | ✅ | `$1..$9`、无 flag 时继续匹配后续 rewrite |
| `last` | ✅ | 重新搜索 location 并从新 location 的 rewrite 模块重新开始 |
| `break` | ✅ | 终止本 location 的 rewrite 模块（**包括 `return`**），然后走内容阶段 |
| `redirect` / `permanent` | ✅ | 302 / 301 + Location，`$is_args` 语义 |
| 替换串带 `?` 时丢弃原 query | ✅ | |
| `if ($var)` / `if ($a = b)` / `~` / `~*` / `!~` / `!~*` | ✅ | 支持 `$http_*` 等变量 |
| `if (-f / -d / -e / -x $var)` 文件测试 | ✅ | |
| `if` 内的 `return` / `rewrite` / `set` | ✅ | `return` 的内容类型按 URI 扩展名 → `default_type` |
| `set $var value` | ✅ | 变量可被后续 `if` / rewrite 引用 |

## stream / mail

| 能力 | 状态 | 备注 |
|---|---|---|
| `stream { server { listen ...; proxy_pass ...; } }` | ✅ | TCP 双向代理 |
| `listen ... udp` | ✅ | UDP 会话按客户端映射上游 socket |
| stream `upstream {}` + 轮询 | ✅ | |
| `proxy_timeout` / `proxy_connect_timeout` | 🟡 | 连接超时生效；`proxy_timeout` 解析但未做空闲断开 |
| stream `return` / `set` / `if` / SSL 终结 | ⬜ | 已解析未执行 |
| `mail {}` | ⬜ | 仅识别并告警 |

## add_header

| 能力 | 状态 | 备注 |
|---|---|---|
| `add_header` 作用于静态响应 | ✅ | |
| `add_header` 作用于代理 / FastCGI 响应 | ✅ | 默认只对 200/201/204/206/301/302/303/304/307/308 生效 |
| `always` 后缀 | ✅ | 对所有状态码生效 |
| `$upstream_cache_status` 变量 | ✅ | MISS / HIT / BYPASS |

## 已知差异（必须修）

1. `add_header` 继承语义与 nginx 不同（nginx：子上下文定义即替换）。
2. 多区间 Range 返回 200 全量，nginx 返回 multipart/byteranges。
3. `server_tokens` 默认值在 http/server 合并时的边界情况。
4. 访问日志不做 `\x` 转义，UA 含引号会破坏行格式。
5. 无 `open_file_cache`，高并发小文件下 stat 次数多于 nginx。
