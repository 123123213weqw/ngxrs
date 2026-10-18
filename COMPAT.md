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
| `-t` / `-T`（含配置 dump） | ✅ | |
| `-e FILE` / `-g DIRECTIVES` / `-p` / `-c`（相对 prefix 解析） | ✅ | |
| `-s stop/quit/reload/reopen` | ✅ | 读 pid 文件后发信号；`reload` 目前等同于 SIGHUP 无动作 |
| `daemon on/off`（fork+setsid、就绪握手、pid 在 listen 之后写） | ✅ | 这是官方测试集能驱动的前提 |
| SIGQUIT / SIGTERM / SIGINT 优雅停止 | ✅ | |
| `error_log` 落盘（notice 级） | 🟡 | 已写文件；分级过滤与 debug 细粒度未做 |
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
| LF-only 行结束符 | ✅ | 与 nginx 一致（官方用例依赖这一点） |
| `Host` 校验（空值 / 端口 / 尾点 / 大小写规范化） | ✅ | |
| absolute-form 请求目标（`GET http://host/p`） | ✅ | 主机取自 URI，空 authority → 400 |
| `#fragment` 丢弃 | ✅ | `$uri` / `$args` 都不含 fragment |
| 错误状态后强制关闭连接（400/405/413/414/495-497/500/501） | ✅ | |
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
| Range（单区间/后缀） | ✅ | 206 + Content-Range |
| 多区间 Range（`multipart/byteranges`） | ✅ | 按 nginx 的 boundary 与分段布局；此前被静默降级成 200 全量 |
| 416 | ✅ | `Content-Range: bytes */size` |
| 条件请求 If-Match / If-Unmodified-Since | ✅ | |
| `sendfile` | ✅ | Linux 走 `sendfile(2)`，非 Linux 回退 read+write |
| `tcp_nopush` / `tcp_nodelay` | 🟡 | 解析并接受，未细调 |
| `try_files`（含末项内部重定向、末尾斜杠目录语义、alias 映射） | ✅ | 与 nginx 12/12 一致 |
| `return` | ✅ | 状态码 + 文本/URL |
| `add_header` | 🟡 | 累加语义（见上） |
| `error_page`（含 `=code`、外部 URL、internal location、非特殊状态码不拦截） | ✅ | |
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
| `proxy_intercept_errors` | ✅ | 状态交给 `error_page`；401 的 `WWW-Authenticate` 跨内部重定向保留 |
| `proxy_limit_rate`（含变量） | ✅ | 限速在**写入前**休眠，客户端看到的是真实速率 |
| `proxy_bind`（源地址绑定） | ✅ | `off` / 地址 / `addr:port` / 变量 |
| `proxy_buffering` | 🟡 | 已解析；当前总是流式转发 |
| 上游失败重试（stale pooled socket） | 🟡 | 仅幂等方法重试同一后端 |
| `proxy_cache` / `proxy_cache_path`（levels/keys_zone/max_size/inactive） | ✅ | 磁盘缓存（原子替换写入），`X-Cache-Status` 走 `add_header $upstream_cache_status` |
| `proxy_cache_valid` / `proxy_cache_key` / `proxy_cache_bypass` | ✅ | 只缓存 `proxy_cache_valid` 列出的状态码 |
| 缓存淘汰（max_size / inactive） | 🟡 | max_size 按 mtime 淘汰；`inactive` 只解析未执行定时清理 |
| `proxy_no_cache` | 🟡 | 已解析，未按变量求值 |
| `proxy_cache_max_range_offset` | ✅ | 起始偏移 ≥ 值（或值为 0）时绕过缓存，让上游看到 `Range` |
| 缓存场景下的 `Range` 处理 | ✅ | 缓存生效时**不把 `Range` 转发上游**（取整实体再切片），绕过时原样转发——ngx_http_upstream_cache_check_range 的语义 |
| 缓存错误状态（nginx `c->error`，ticket #827） | ✅ | 被拦截的上游错误以「无 body 的错误条目」入缓存，后续请求重放该错误；`bypass` 不写 |
| `fastcgi_pass` / `fastcgi_param` / `fastcgi_index` / `fastcgi_split_path_info` | ✅ | FastCGI 1.0 记录协议；`$fastcgi_script_name`、`$fastcgi_path_info` 等变量 |
| FastCGI 无 Content-Length 时用 chunked | ✅ | 与 nginx 帧格式逐字节一致 |
| `fastcgi_connect_timeout` / `fastcgi_read_timeout` | ✅ | |
| `fastcgi_cache` / `fastcgi_buffers` / `fastcgi_keep_conn` | ⬜ | 已解析未生效 |
| `uwsgi_pass` / `uwsgi_param` | ✅ | 报文头 `modifier1, size(LE16), modifier2`（按 nginx 源码） |
| `scgi_pass` / `scgi_param` | ✅ | netstring + NUL 分隔键值对 |
| `grpc_pass` | ⬜ | |

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
| HTTP/2（多路复用、`:authority` 选虚拟主机、头部规范化） | 🟡 | 功能可用；帧级已对齐到 `h2.t` **116/145**、`h2_headers.t` **71/112**（此前都是 0）。剩余差异见下方「HTTP/2 残余差异」 |
| `http2 on`（http/server 级，nginx 1.25.1+） | ✅ | 含 http→server 继承 |
| h2c prior-knowledge（明文 HTTP/2） | ✅ | 探测连接前言，仅在该组配置了 `http2 on` 时启用 |
| `$scheme` | ✅ | 此前恒为 `http`，TLS 连接上也报 `http`；现按连接推导 |
| `ssl_verify_client` / `ssl_client_certificate` | 🟡 | 12/16，见下节 |
| `grpc_pass` / `resolver` | ✅ | `grpc_pass.t` 7/7；`grpc_ssl.t` 17/40 |
| `mail`（pop3/imap/smtp + auth_http） | ✅ | smtp 43/43、pop3 30/30、imap 33/33，全部与 nginx 一致 |
| `large_client_header_buffers` | ✅ | http/server 级；h1 用 `size`，h2 用 `size` 做单字段上限、`size*num` 做整块上限（与 `ngx_http_v2_state_header_complete` 一致，按 `name.len+value.len` 计，含伪头） |
| HTTP/2 SETTINGS / WINDOW_UPDATE 帧 | ✅ | 与 nginx 逐字节一致：`MAX_CONCURRENT_STREAMS=128`、`INITIAL_WINDOW_SIZE=65536`、`MAX_FRAME_SIZE=16777215`，外加连接级 `WINDOW_UPDATE 0x7fff0000` |
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

## HTTP/2 / TLS 官方用例实测（本轮）

放开 `-V` 后这些套件才真正运行，此前全部被静默 skip：

| 用例 | ngxrs | nginx |
|---|---|---|
| `h2.t` | **116/145** | 145/145 |
| `h2_headers.t` | **71/112** | 112/112 |
| `h2_host.t` | **52/62** | 48/62 |
| `h2_keepalive.t` | 12/21 | 21/21 |
| `h2_error_page.t` | 3/4 | 4/4 |
| `h2_proxy_cache.t` | 10/11 | 11/11 |
| `ssl_sni.t` | 4/10 | 10/10 |
| `ssl_verify_client.t` | **12/16** | 16/16 |

## mail（pop3 / imap / smtp，三个用例全部与 nginx 一致）

`mail {}`：`server{}`、`listen ... [pop3|imap|smtp]`、`protocol`、`server_name`、
`auth_http`、`auth_http_timeout`、`proxy_timeout`、`proxy_pass_error_message`、
`pop3_auth` / `imap_auth` / `smtp_auth`（含 `none`；mail 主上下文亦可）；
三种协议的认证阶段（USER/PASS、APOP、AUTH PLAIN/LOGIN/CRAM-MD5/EXTERNAL，
含 IMAP 的同步 `{N}` 与非同步 `{N+}` 字面量）；auth_http 的 HTTP/1.0 请求与
`Auth-Status/Server/Port/Pass/User/Error-Code/SMTP-To` 解析；认证成功后的
后端拼接。

**实测（nginx 1.28 对照，同机同配置）：**

| 用例 | ngxrs | nginx |
|---|---|---|
| `mail_smtp.t` | **43/43** | 43/43 |
| `mail_pop3.t` | **30/30** | 30/30 |
| `mail_imap.t` | **33/33** | 33/33 |

### 与 nginx 对齐时修掉的真缺陷

1. **`smtp_auth none` 的乐观应答模型**：nginx 对 `MAIL FROM` 先自己回
   `250 2.0.0 OK`，随后才连后端，并**吞掉后端对这一条的应答**；`RSET` 在
   尚未建立代理时同样由 nginx 自己回答。
2. **`Auth-Method` 必须小写**（`external` / `cram-md5` / `none`）。
3. **`Auth-Salt`**：CRAM-MD5 的挑战要作为 `$auth_salt` 传给 auth_http（三种
   协议都要）。
4. **后端问候一律丢弃**：客户端早已收到我们的问候，转发会造成每条响应错位。
5. **POP3 后端的 USER 应答丢弃、PASS 应答转发**；且无论客户端用哪种机制，
   发给后端的都是 `USER`/`PASS`。
6. **IMAP 与后端是分步对话**：先发 `{N}`，等 `+` 再发内容。一次性写入会让
   用缓冲行读（Perl `<>`）的后端把字面量吞进自己的缓冲区而挂死。
7. **IMAP `AUTHENTICATE` 只把机制名大写**，且支持 inline initial response。
8. **IMAP 字面量** `{N}` / `{N+}`，引号串的 `\"` 与 `\\` 反转义。

### 能力协商与 STARTTLS

`starttls off|on|only`、`{imap,pop3,smtp}_capabilities` 已实现，能力串与
nginx 逐字节一致；`STLS` / `STARTTLS` 执行**真实的 TLS 升级**（rustls），
已用 `openssl s_client -starttls imap|pop3|smtp` 三种协议验证握手成功。

**隐式 TLS**：`listen ... ssl` 从第一个字节起就是 TLS（在问候之前完成握手），
且 mail `server` 内的 `ssl_certificate` 覆盖 mail 块的证书。已实测：明文连接
拿不到问候，TLS 连接拿到 `* OK IMAP4 ready`。

**实测（nginx 1.28 对照）：**

| 用例 | ngxrs | nginx |
|---|---|---|
| `mail_capability.t` | **19/19** | 19/19 |
| `mail_pop3.t` | **30/30** | 30/30 |
| `mail_imap.t` | **33/33** | 33/33 |
| `mail_smtp.t` | **43/43** | 43/43 |

`mail_ssl.t` / `mail_imap_ssl.t` 在 **nginx 自己**上也只跑到 2 条断言就中止
（依赖 `ssl_password_file` 等），因此**不作为兼容性证据**。

### 其余 mail 用例（A/B 实测，nginx 1.28 为基准）

| 用例 | ngxrs | nginx | 缺口 |
|---|---|---|---|
| `mail_smtp_xclient.t` | **8/8** | 8/8 | 一致 |
| `mail_proxy_smtp_auth.t` | 8/9 | 9/9 | 1 |
| `mail_smtp_greeting_delay.t` | **4/4** | 4/4 | 一致 |
| `mail_resolver.t` | 9/12 | 12/13 | 3 |
| `mail_max_errors.t` | 14/20 | 20/20 | 6 |
| `mail_error_log.t` | **32/32** | 32/32 | 一致 |

### 仍未实现

- `max_errors` 的完整语义
- mail 侧的 `ssl_verify_client`
- `error_log` 的细粒度事件（各模块自己产生的 debug 级消息）尚未补全
- **`limit_conn.t` 9/10**：剩下 1 条是「客户端关闭后立刻释放名额」。nginx 在
  连接关闭的瞬间归还 slot；我们是在那次在途上游请求结束（含 `limit_req`
  延迟）之后才归还，所以紧跟其后的请求仍看到计数未清零。
  这条**会偶发通过**（曾出现过 10/10），连跑三次稳定为 9/10，因此按 9/10 记录
- **`stream` 的 TLS 终止已实现**（`listen ... ssl`，证书可从 `stream {}` 继承），
  `stream_ssl.t` **7/7 与 nginx 完全一致**
- **`stream` 上游 TLS 已实现**：`proxy_ssl on`、`proxy_ssl_session_reuse`
  （rustls 的 resumption 缓存按 SNI 共享，所以第二次连接会复用会话）、
  `proxy_ssl_name`，以及 stream server 的 `return <text>`（会展开
  `$ssl_session_reused` → `.` / `r`）。

| 用例 | ngxrs | nginx |
|---|---|---|
| `stream_ssl.t` | **7/7** | 7/7 |
| `stream_proxy_ssl.t` | **8/8** | 8/8 |
| `stream_error_log.t` | **36/36** | 36/36 |

`stream {}` 级的 `proxy_connect_timeout` / `proxy_timeout` 之前是
「接受但忽略」，现在真正生效并按 server 覆盖（默认 60s / 10m，与 nginx 一致）。

- `stream_ssl_verify_client.t`（stream 侧客户端证书校验）未实现，仍为 UNRUN
- 「因未声明模块而被静默跳过」的用例现在会被 harness 显式标成 **UNRUN**，
  不再混进 SAME

### 本轮修掉的真缺陷

1. **`pop3_auth` / `imap_auth` / `smtp_auth` 必须按协议分开存**。nginx 把它们
   放在各自的 server 配置里；我之前共用一个集合，导致 mail 主上下文的
   `pop3_auth plain apop cram-md5` 泄漏到 imap 和 smtp，能力串多出
   `AUTH=CRAM-MD5` / `CRAM-MD5`。
2. **`*_auth` 的默认值是 `plain`**（LOGIN 无条件叠加），不是「全开」。
3. **只有 mail（或只有 stream）的配置无法启动**：HTTP worker 0 发现没有
   listen socket 就 `exit(1)`。现在没有 http 监听时跳过 HTTP 侧并立即完成就绪握手。
4. 能力串拼装顺序与 nginx 一致：IMAP 为
   `<caps> AUTH=... STARTTLS [LOGINDISABLED]`（**AUTH= 不含 LOGIN**）；
   POP3 为 `TOP USER UIDL SASL ... STLS`，`only` 时去掉 USER 与 SASL；
   SMTP 为 `250-<name>` 后逐个能力行，最后一行用 `250 `，且**没有 8BITMIME**。

## gRPC

`grpc_pass` 已实现：`grpc://`（h2c）、`grpcs://`（TLS + ALPN h2）、直接写
`upstream {}` 的名字（nginx 先剥掉 scheme 再查 upstream 表，所以 `grpc://u`
命中的是 `upstream u` 而不是一次 DNS 查询）、以及含变量的目标。

变量目标需要 `resolver`，因此新增了 **`resolver` 指令 + 最小 DNS 客户端**
（`src/resolver.rs`，A 记录，带 TTL 缓存）。这同时也让 `proxy_pass` 用变量
时有了回退解析能力。

`grpc_pass.t` **7/7 与 nginx 断言数完全一致**。

顺带修掉两个真实缺陷：

1. **TLS 判定粒度错了**：`ssl` 之前记在 server 上，于是
   `server { listen 8081; listen 8082 ssl; }` 会把 8081 也变成 TLS。
   nginx 是按 **listen socket** 决定的，现改为每个 listen 各自带 `ssl` 标记。
   这个 bug 让整个 grpc_pass.t 从 404 变成可测。
2. `grpcs://` 的 SNI 直接用了 `host:port`，`ServerName` 解析失败。

## TLS 客户端证书

`ssl_verify_client on|off|optional|optional_no_ca`、`ssl_client_certificate`、
`$ssl_client_verify` / `$ssl_client_cert` / `$ssl_protocol` / `$ssl_cipher` /
`$ssl_server_name` 均已实现。`ssl_verify_client.t` 从 2/16 提升到 **12/16**
（nginx 16/16）。

设计要点：nginx 在客户端证书不合格时**不中断握手**，而是回一个 400
（内部码 495/496）。rustls 的 `WebPkiClientVerifier` 会在握手中直接拒绝，
客户端只会看到 TLS alert。因此这里用一个「请求但不拒绝」的验证器，把判定推迟到
HTTP 层、按请求命中的 virtual host 做，与 `ngx_http_process_request_headers`
里读 `sscf->verify` 的做法一致。

**剩余 3 条无法达标的原因**：nginx-tests 生成的证书是 **X.509 v1**，而
rustls/webpki 直接拒绝 v1（`UnsupportedCertVersion`）；OpenSSL 没有这个限制。
握手层已容忍（否则带客户端证书的连接完全不可用），但链校验仍会如实失败，
所以 `$ssl_client_verify` 报 `FAILED:...` 而非 `SUCCESS`——不会把没验证过的
证书说成已验证。

## HTTP/2 残余差异

对齐帧格式后，官方用例剩下的失败**集中在两类**，都不是内容层：

1. **HPACK 编码选择**（`h2_headers.t` 的 huffman / 索引模式 / 动态表边界，约 20 条）。
   nginx 自己实现 HPACK，选择是否 huffman、用哪种索引模式；`h2` crate 用的是另一套
   实现，两者都符合 RFC 但字节不同。用例断言的是 nginx 的具体选择，要匹配只能自己写
   HPACK 编码器。
2. **连接级错误的帧形态**（GOAWAY 的 code/时序、`PUSH_PROMISE` 拒绝、非法前言、
   `http2_max_concurrent_streams` 的 RST_STREAM 细节，约 25 条）。`h2` crate owns
   framing，我只能在 `accept()` 之后介入，改不了它发出的 GOAWAY。
3. `large_client_header_buffers` 超限：nginx 发 `GOAWAY(ENHANCE_YOUR_CALM)`，我们回
   431 —— 用例只断言「没有 DATA 帧」，所以这部分已通过，但帧形态仍不同。

## 已知差异（必须修）

1. `add_header` 继承语义与 nginx 不同（nginx：子上下文定义即替换）。
2. `server_tokens` 默认值在 http/server 合并时的边界情况。
3. 访问日志不做 `\x` 转义，UA 含引号会破坏行格式。
4. 无 `open_file_cache`，高并发小文件下 stat 次数多于 nginx。
5. `proxy_cache_min_uses` 只解析未生效。


## nginx-tests 状态（官方 Perl 测试集）

`bench/nginxtests.sh` 对**同一组用例分别跑 nginx 和 ngxrs**，再逐条断言对比。

绝对通过率在这里没有意义：master 分支的用例按较新的 `Test::Nginx` 编写，
而 CPAN 上最新只有 0.32/0.33，其 `http()`→`http_end()` 是 slurp 读法，
HTTP/1.1 keepalive 响应会一直阻塞到 8s 超时并返回 `undef`。**真 nginx 跑同一套也得同样的失败。**
所以脚本只报告两个数字：nginx 通过但我们失败的断言数（真缺陷），以及反之。

> 上一轮我写「http_keepalive.t 4/21，失败集中在 keepalive 细节，是真实差距」——**这个结论是错的**。
> 那批失败全部来自上述框架版本问题；用 nginx 做对照后，两者的逐文件数字完全相同。
> 本轮已改为 A/B 对比，并把此前被误判为"环境问题"的几个真实缺陷揪了出来（见下）。

### 本轮由官方用例发现的真实缺陷（已修）

| 缺陷 | 影响 | 修复 |
|---|---|---|
| 只接受 CRLF 行结束符 | 发 LF-only 请求的客户端永远读不到响应 | `find_header_end` / `split_lines` 同时接受 LF 与 CRLF |
| `$host` 未规范化 | 大写、带端口、尾点的主机名全部不匹配 | 小写、去端口、去尾点；`.` 单独出现视为非法 |
| absolute-form 未取 URI 主机 | `GET http://l/` 时 `$host` 取错 | 绝对形式优先于 Host 头；空 authority → 400 |
| `#fragment` 未丢弃 | `$uri` / `$args` 里混入 fragment | 解析 target 时先按 `#` 截断 |
| `Host` 校验缺失 | 空值 / `:port` / 非数字端口未返回 400 | 按 nginx 规则校验 |
| `add_header` 只对静态生效 | `return`、FastCGI、代理响应都缺头 | 移到响应解析出口统一应用 |
| `server_name` 优先级错误 | 通配符不取最长、`*.a.b` 不吃多级、尾缀通配未实现 | 按 nginx 顺序重写匹配 |
| `server_name ~` 不支持 `\Q..\E` 与命名捕获 | 正则服务器名不生效 | 翻译 `\Q..\E`，命名捕获暴露为变量 |
| 错误状态不关连接 | 405/400 后仍保持 keepalive，客户端等 EOF 会挂 | 按 nginx 的 400/405/413/414/495-497/500/501 强制关闭 |

### 当前 A/B 结果

`bench/nginx_tests.sh` 逐文件对比；`bench/ntscan.sh` 自动扫
http/proxy/upstream/range/fastcgi/scgi/uwsgi/stream/limit 各类用例，
只报告「nginx 过而 ngxrs 不过」的真缺陷。

最近一次全扫（39 个参评文件 / 21 个双方都跳过）：

| | 数量 |
|---|---|
| 与 nginx 断言数**完全一致** | **34**（含 `proxy_cache_lock` 19/19、`proxy_cache_lock_age` 6/6、`proxy_cache_max_range_offset` 9/9、`h2_host`） |
| **优于** nginx | **3**（`http_headers_multi` 49 vs 48、`http_host` 58 vs 62、`proxy_cache_range` 9 vs 8） |
| 更差 | 0 |

> **上述数字不完整（已发现并修正）**：`-V` 之前只打印版本号，而 Test::Nginx 用
> `-V` 文本判断哪些用例能跑——未知特性按**字面子串**匹配。于是 `http_v2`、`ssl`、
> `stream` 相关套件被静默 skip，在扫描里表现为「双方都跳过」，把真实差距藏了起来。
> 现在 `-V` 会输出 `configure arguments:`（只列真正实现的模块，缺失的用
> `--without-` 明确标出）。放开后立刻暴露：`h2.t` **0/145**（nginx 145/145）、
> `h2_headers.t` **0/112**。这些数字必须计入，不能只报「34/39 一致」。

完全一致的用例（断言数与 nginx 相同）：`http_location` 16/16、`http_uri` 21/21、
`http_server_name` 22/22、`http_method` 4/6、`http_try_files` 12/12、
`http_error_page` 11/11、`http_include` 7/7、`http_absolute_redirect` 25/25、
`http_header_buffers` 10/12、`http_expect_100_continue` 5/7、`fastcgi_body` 7/7、
`http_variables` 9/9、`http_keepalive` 21/21、`proxy_available` 4/4、
`proxy_bind` 7/7、`limit_req` 8/8、`proxy_cache_lock_age` 6/6、
`proxy_cache_lock_ssi` 4/4。

### 剩余差距（21 条断言）

| 用例 | 差 | 缺什么 |
|---|---|---|
| proxy_cache_control.t | 11 | 上游 `Cache-Control`/`Expires`/`X-Accel-Expires` 的完整优先级与 `$upstream_cache_status` 细节 |
| proxy_cache_convert_head.t | 2 | `proxy_cache_convert_head`（HEAD 转 GET 后缓存） |
| proxy_cache_chunked.t | 1 | chunked 上游响应的缓存 |
| proxy_cache_lock.t | 1 | lock 超时后并发回源的细节 |
| http_headers_multi.t | 1 | `$sent_trailer_*`（需要发送 trailer） |
| http_keepalive_shutdown.t | 1 | 依赖 `limit_req` 的延迟时序 |
| proxy_cache_bypass.t | 4 | `proxy_cache_bypass` 的多变量求值 |

### 本轮由官方用例发现并修复的缺陷

| 缺陷 | 影响 |
|---|---|
| **`proxy_bind` 完全缺失** | 无法指定回源源地址；现已支持 `off`/地址/`addr:port`/变量（`$remote_addr`/`$remote_port`/`$arg_*`），并沿用 server 级继承 |
| **`limit_req` / `limit_conn` 完全缺失** | 无任何限流能力；现实现漏桶（`rate`/`burst`/`nodelay`/`delay`）与并发连接计数，相位与 nginx 一致（PREACCESS，早于代理） |
| **`$request_time` 等变量在代理响应头里不展开** | `add_header` 走的是代理专用替换，只认 3 个变量；现改为完整变量解析器 |
| **`$remote_port` 缺失** | |
| **keepalive 空闲超时用 server 级而非 location 级** | 刚服务完的请求其 location 的 `keepalive_timeout` 才决定下一次读 |
| **关闭时未通知客户端** | 优雅停机期间响应应带 `Connection: close` |
| **`proxy_cache` 不认上游 `Cache-Control`/`X-Accel-Expires`/`Expires`** | 只认 `proxy_cache_valid`，导致大量上游显式声明可缓存的响应没被缓存 |
| **close-delimited 上游响应无法缓存** | 要求有 `Content-Length` 才缓存；nginx 会缓冲到 EOF 并补发长度 |
| **`proxy_cache_lock` 未实现** | 冷启动并发会重复回源 |
| **配置热重载（SIGHUP）完全缺失** | `nginx -s reload` 无效；现已实现：解析新配置、原子替换 `Arc<Config>`，在跑连接继续用旧快照 |
| **优雅停机不等在途请求** | SIGQUIT/stop 会打断正在流式输出的响应；现先停 accept 再等 `ACTIVE_CONNS` 归零（30s 上限） |
| **上游 close-delimited 响应未重分帧** | 无 Content-Length 也无 TE 的上游响应原样转发，客户端无法判断结束；现转为 chunked |
| **上游响应不认 LF-only 行结束符** | 简单后端（Perl heredoc）用 LF，我们找不到头就 502 |
| `set` 变量传不到 `add_header` | `set $limit_rate 40k; add_header X-Rate $limit_rate;` 取不到值 |
| `$limit_rate` 未按速率解析 | 返回 `40k` 而不是 `40960`；非法值应为 `0` |
| access_log 缺 `$uri` / `$sent_http_*` | 变量为空；重复响应头未逗号合并 |
| access_log 缺「变量未命中写 `-`」 | nginx 对 not-found 变量输出 `-` |
| 请求目标非法时不写 access log | |
| `expires` 未实现 | `epoch`/`max`/相对时间，且必须**替换**上游的 `Cache-Control` |
| ssl/`log_format` 之外的：nginx 默认 pid 与 error_log 路径 | 现默认 `<prefix>/logs/{nginx.pid,error.log}` |
| **keepalive 连接缓冲未清空** | `consume` 只把 start/end 归零，`buf` 仍留着上一个请求的字节；下一个请求会重新解析到旧数据（`http_header_buffers.t` 6/12 → 10/12） |
| HTTP/2 上的反向代理返回 502 | 新增 socket-free 的 `proxy::fetch`，h2 请求现在能代理 |
| `Expect: 100-continue` 从未响应 | 客户端等 100 才发 body，直接挂住；现按 RFC 只对 HTTP/1.1 发送 |
| `$http_*` 未合并重复请求头 | 多值头只取第一个 |
| 缺 `$cookie_*` / `$sent_http_*` / `$upstream_http_*` / `$upstream_cookie_*` / `$remote_user` | 大量变量为空 |
| `add_header` 只取 args[1] | `always` 被丢弃，值里的空格被截断 |
| `add_header` 求值顺序错误 | 后面的头看不到前面的，`$sent_http_*` 失效 |
| `if` 用另一套变量展开（`RwVars`） | `$arg_*` / `$cookie_*` 在 `if` 里恒为空 |
| 缺 `allow` / `deny` / `limit_except`（access 模块） | 访问控制完全缺失 |
| 访问控制在 405 之后才执行 | 应 403 的请求返回 405 |
| server 级 `if` / `set` 未实现 | |
| `$upstream_addr` 缺失 | |
| `absolute_redirect` / `server_name_in_redirect` / `port_in_redirect` 未实现 | |
| `Location` 未做 URI 转义 | 带空格/特殊字符的路径原样输出 |
| 无 Host / Host 非法时未回退到本地地址 | |
| 解析阶段 400 未走 error_page | |
| nginx 的「唯一头」规则未实现（Host/CL/TE/Expect/If-*/Authorization/Content-Range） | 重复头未拒绝 |

### 当前 A/B 结果（8 个用例文件）

| 用例 | nginx | ngxrs | 备注 |
|---|---|---|---|
| http_location.t | 16/16 | **16/16** | |
| http_uri.t | 21/21 | **21/21** | |
| http_server_name.t | 22/22 | **22/22** | |
| http_method.t | 4/6 | **4/6** | |
| http_try_files.t | 12/12 | **12/12** | |
| http_error_page.t | 11/11 | **11/11** | |
| http_host.t | 54/62 | **58/62** | 我们多过 4 项 |
| http_keepalive.t | 21/23 | 18/23 | 剩 `keepalive_time` 的计时语义 |

合计断言：nginx 161 / ngxrs 162；6 个文件完全一致，1 个更好，1 个更差。

### 本轮由官方用例发现并修复的缺陷

| 缺陷 | 影响 |
|---|---|
| `try_files` 语义整体错误 | 末项未做内部重定向、末尾斜杠未剥离、未区分文件/目录、alias 位置映射错误 |
| `alias` 偏移属于嵌套 location 而非声明它的 location | 嵌套 alias 全部指向错目录 |
| `error_page` 不支持外部重定向目标（`http://…`） | `error_page 302 http://…` 被当成文件路径 |
| `error_page` 目标中的 `$arg_*` 与查询串未展开 | `?$arg_a` 原样发出 |
| 497 隐含 302 未实现 | |
| 错误页内部重定向后未跑 rewrite | `rewrite ^ http://…` 型错误页失效 |
| 错误页产生的 3xx 被原状态覆盖 | 目录 auto-redirect 变成 302 |
| `error_page` 对非「特殊状态码」（如 418）也生效 | 与 nginx 不符 |
| 缺 `auto_redirect`（`location /a/` 时 `/a` → 301） | |
| `Keep-Alive: timeout=N` 响应头缺失 | |
| `keepalive_requests` / `keepalive_timeout` 无 location 级覆盖 | |
| `keepalive_time` / `keepalive_disable` / `$connection_requests` / `$connection_time` 缺失 | |
| 405 被当作强制关连接 | POST/PUT 的 405 应保持 keepalive |
| `$server_name` 未去掉前导点、空值 `add_header` 未省略 | |
| dispatch 二次解析目标导致 rewrite 后 location 错配 | `rewrite … break` 语义回退 |

### 访问控制在内容处理器之前执行（安全相关）

nginx 的相位顺序是 `POST_READ → SERVER_REWRITE → FIND_CONFIG → REWRITE →
POST_REWRITE → PREACCESS → ACCESS → POST_ACCESS → PRECONTENT → CONTENT`。
`proxy_pass` / `fastcgi_pass` / `scgi_pass` / `uwsgi_pass` / `grpc_pass` 走的是
CONTENT，所以 ACCESS 必须先求值。

在修复前，这些上游处理器在 `route` 之前就被分派，导致：

| 配置 | 修复前 | 修复后 | nginx |
|---|---|---|---|
| `location / { auth_basic …; proxy_pass …; }` | **200**（未认证放行） | 401 | 401 |
| 同上 + 正确凭据 | 200 | 200 | 200 |
| `location / { deny all; proxy_pass …; }` | **200** | 403 | 403 |

同时修正 `auth_request_set $args …`：它写回 `r->args`，改写后的查询串必须传给上游。

### 当前 A/B 结果（本机 nginx 1.28.0 对照，逐条断言）

| 用例 | nginx | ngxrs | 备注 |
|---|---|---|---|
| http_location.t | 16/16 | 16/16 | 一致 |
| http_server_name.t | 22/22 | 22/22 | 一致 |
| http_uri.t | 21/21 | 21/21 | 一致 |
| http_method.t | 4/6 | 4/6 | 一致（双方共享的失败） |
| http_variables.t | 9/9 | 9/9 | 一致 |
| auth_request_satisfy.t | 20/20 | 20/20 | 一致 |
| auth_request_set.t | 8/8 | 8/8 | 一致 |
| auth_request.t | 22/22 | **19/22** | 缺：auth 子请求缓存、请求体回放、多个 `WWW-Authenticate` |
| proxy_cache_lock.t | 19/19 | 19/19 | 一致 |
| proxy_intercept_errors.t | 6/6 | 6/6 | 一致 |
| proxy_cache.t | 17/17 | **14/17** | 差 3 条 |
| ssi.t | 32/32 | **30/32** | 差：代理响应上的 SSI |
| access.t | 14/14 | 14/14 | 一致（`listen unix:` / `allow unix:` / `proxy_pass http://unix:`）|
| h2.t | 144/145 | **115/145** | HPACK 编码与连接级帧形状由 `h2` crate 决定 |
| h2_host.t | 48/62 | **52/62** | 我们多过 4 条 |
| h3_headers.t | 无基线 | 28/77 | 本机 nginx 无 `--with-http_v3_module` |

自建差分套件 `bench/all.sh`：**70/70**（静态 19 + 功能 28 + TLS/H2 9 + fastcgi/ugcgi/grpc/stream 14）。

### 尚未实现

- `stream` 上的 `listen unix:`（HTTP 已支持）
- HTTP/3 与 nginx 的逐帧一致（本机无法建立基线）
- `auth_request` 子请求缓存、`max_errors`、`stream`/`mail` 客户端证书校验
- 高并发（c≥1024）吞吐约为 nginx 的 0.94–0.95×；64KB 尾延迟优于 nginx 一个数量级

## 本轮已知回归（未修复）

- `proxy_cache_vary.t`：手工跑 48/54，nginx 53/54；经 A/B 脚本跑时更会被判定为
  UNRUN（脚本以 `prove -v > file` 运行，本次运行会卡住直到 150s 超时，TAP 输出丢失）。
  已排除的原因：`serve_cached` 里的 gzip（关掉它之后 vary 仍然失败，只是
  `proxy_cache.t` 从 17/17 掉到 15/17，已恢复）。根因尚未定位，失败集中在
  需要重启服务器的用例（`cold first/second`）与 Vary 归一化用例
  （`normalize first`、`vary asterisk second`）。
- `proxy_cache_use_stale.t`：25/36（上一轮 26/36），差集主要是 `updating` /
  `revalidated` 事件，两者都还没有实现。

## 本轮修复（proxy_cache_vary 回归）

上一轮报告的 `proxy_cache_vary.t` 48/54 回归已修复，现在 **53/54，与 nginx 一致**
（唯一失败项是该用例自带的 TODO `normalize order`，nginx 同样失败）。根因不止一个：

1. `Vary` 归一化（RFC 7234 §4.1）缺失：只按逗号切分并去空白/空项。
   `foo, bar`、`foo,bar`、`foo,,  ,bar , ` 必须等价。
2. 主键查询顺序错误：`load(base) || load_variant(...)` 让一个没有 `Vary` 的旧条目
   命中所有后续请求。nginx 先读主条目的 vary 名单，有名单才去查变体。
3. `Vary: *` 必须完全不缓存（RFC 7231 §7.1.4）。
4. `gzip_vary` 只在真正压缩时才发 `Vary: Accept-Encoding`；nginx 在
   "可 gzip"（状态/类型/长度达标）阶段就发，与客户端是否接受 gzip 无关。
   这一点会直接改变上游返回的头，从而改变缓存的键。
5. 变体索引文件的多进程读-改-写没有加锁（`flock`），并发写会丢行。
6. `proxy_cache_revalidate` 的 304 刷新写回主键而不是变体键。

另外两个与本用例无关但被它暴露出来的真问题：

7. **退出时不删除 pid 文件**（nginx 的 `ngx_delete_pidfile`）。官方 harness 的
   `run()` 轮询 pid 文件判断"已启动"，残留的旧文件让它在 socket 尚未 bind 时
   就发请求，表现为 `undef`。这一条同时影响所有 `$t->stop(); $t->run();` 的用例。
8. **优雅退出不关闭空闲 keepalive 连接**：`$t->stop()` 要等到 `keepalive_timeout`
   才返回（实测 20s+，现在 0.1s）。nginx 的 `ngx_close_idle_connections` 立即关闭。
9. `limit_req` 的延迟用 `std::thread::sleep` 在 async 路径上**阻塞 runtime 线程**。
   多 worker 时被掩盖，单 worker 时整个服务器被串行化（`limit_conn.t` 因此从 9/10
   掉到 5/10）。改为 `tokio::time::sleep` 后恢复 9/10。

顺带：`worker_processes` 默认值改为 1（nginx 的默认值；`auto` 仍是 CPU 数），
补上 `$request_time`，`gzip` 对 HEAD 也应发 `Content-Encoding: gzip`（已用 nginx 探测确认）。

已知未完成：`proxy_cache_use_stale.t` 27/36（缺 `updating`/`revalidated` 事件），
`limit_req_delay.t` 4/6（`delay=N` 的排队语义），`limit_conn.t` 9/10（客户端一断开
就要立刻释放名额）。

## 本轮（limit_req 漏桶按 nginx 单位重写 + limit_conn 名额回收 + proxy_pass 变量目标）

### limit_req：`delay=N` 之前完全没生效

用真 nginx 探到的三点（`rate=30r/m`，即每 2s 一个请求）：

| 配置 | 行为 |
|---|---|
| `burst=2 nodelay` | 前 3 个立刻 200，第 4 个 503 |
| `burst=2`（无 delay/nodelay） | 第 1 个立刻，之后每个延迟 2s 后 200（**不拒绝**） |
| `delay=1 burst=2` | 前 2 个立刻，之后每个延迟 2s 后 200 |

原来的实现用 `interval * excess` 估延迟，且把 `nodelay` 和 `excess==1` 混在一起，
`delay=N` 只解析不使用。现改为 nginx 的**毫请求单位**（1000 = 一个请求，
`rate` 为毫请求/秒，新节点从 -1000 起）：

```
excess = excess - rate*ms/1000 + 1000
if excess > burst*1000      -> 503（且不记账）
if excess > delay*1000      -> 延迟 (excess - delay*1000)/rate 秒
```

`limit_req_delay.t` 4/6 → **6/6**，`limit_req.t` 保持 8/8。

### limit_conn：客户端断开的瞬间释放名额

nginx 在连接可读事件里立刻回收（`ngx_http_limit_conn_cleanup`）。我们没有共享内存，
只能在"下一个请求做判定时"补一次检查：`ConnZone` 现在保存每个名额的客户端 fd，
达到上限时先 `recv(MSG_PEEK)` 探活，已关闭的名额直接回收。另外代理等待上游时
也 `select!` 一个客户端断开探测（仅在该 location 有 `limit_conn` 时启用）。
`limit_conn.t` 9/10 → **10/10**（连跑三次稳定）。

### proxy_pass 的变量目标

`proxy_pass http://$arg_b` 之前直接 502：变量展开用的是 `src/proxy.rs` 里另写的
第二个展开器，它不认 `$arg_*`（和之前 `RwVars` 那个坑同一类）。现在：

- 未知名字回落到 `ServerVars::get`，两套实现不会再漂移；
- 变量目标的 authority 在请求时展开，先按 `upstream {}` 名字匹配，否则 IP 直连或
  用 `resolver`；
- 展开值里的 URI 部分（`host/`）替换请求 URI，且**不**追加原查询串（实测 nginx 行为）。
- 补上 `$proxy_host` / `$proxy_port` / `$proxy_add_x_forwarded_for`（`add_header` 用）。

`proxy.t` 12/30 → **17/30**（4 条剩余都是 `$upstream_header_time` / 重试尝试列表）。

### 允许清单（诚实）
`proxy.t` 剩余 4 条：慢响应头下的 `$upstream_header_time`，以及 next_upstream 后
`$upstream_response_time` / `$upstream_header_time` 的逗号列表（我们只存单次值）。
`proxy_cache_use_stale.t` 27/36（缺 `updating`/`revalidated` 事件）。

## 本轮（$upstream_*_time、location access_log、log_format 拼接）

### proxy.t 12/30 → 30/30，与 nginx 完全一致

三处缺口，都是先看测试怎么断言、再对 nginx 探测确认的：

1. **`$upstream_connect_time` / `$upstream_header_time` / `$upstream_response_time`
   根本不存在**。新增 `src/timing.rs`：按 nginx 的语义为**每次尝试**记录一个条目，
   用 `, ` 连接，未取到的值打印 `-`。值在**发送响应头时**求值，所以正在应答的那次
   尝试还没有 response time——这正是 `proxy.t` 的 `rt2 == '-'` 断言。
   放在 task-local 里：同一个连接任务内既能在代理深处写、又能在访问日志处读。

2. **location 级 `access_log` 未实现**，所以 `access_log %%TESTDIR%%/time.log time;`
   一个字节都没写；`$t->read_file('time.log')` 直接 die，测试在第 21 条断言后中止。
   现在 `LocCfg.access_logs: Option<Vec<AccessLog>>`，`None` 表示继承 server。

3. **`log_format` 的相邻字符串被我用空格拼接**。nginx 是**直接相连**（这正是
   `'...connect:header:' 'response...'` 拆行写法的用途）。结果日志里多出空格，
   正则匹配不上。

4. 客户端提前断开时，nginx 会立刻终结上游请求（header time 保持 `-`）。我们原来只在
   有 `limit_conn` 的 location 上探测客户端断开；现在对所有代理请求探测，步长 1ms
   起、200ms 后放宽到 10ms。

### 测试框架的又一个盲点（已修）

`proxy.t` 曾显示 `SAME nginx 30/30 ngxrs 21/30`——因为我们的运行**中途 die**，
没产生任何 `not ok` 行，逐条 id 对比自然找不到「更差」。这与之前 `h2.t` 的
UNRUN 是同一类问题。现在断言行数少于参考运行的一律进 `TRUNC` 桶并让脚本失败。

### 回归
31 个用例文件：29 个完全一致，2 个更好（`http_host` 58 vs 54、`http_headers_multi`
49 vs 48），0 个更差，0 个截断；断言总数 ngxrs 606 / nginx 601。
自建差分套件 70/70；单测 101。

## 本轮（location 正则捕获变量、proxy_pass URI 变量、background update 等它完成）

### 新的真缺陷：location 正则的捕获根本不是变量

`location ~ /(reg)(?P<name>exp).html { proxy_pass http://u/$1$name.html; }` 我们
返回 404。两个缺口叠在一起：

1. **location 正则的 `$1..$9` 与命名组从未被采集**。之前只有 `server_name ~`
   的捕获会进变量表，location 的捕获根本没有落到 `custom` 里，所以任何
   `$1`/`$name` 在 `proxy_pass`、`fastcgi_param`、`add_header` 里都是空串。
   新增 `Server::locate_with_captures`：赢家是正则 location 时把捕获并入变量表。
2. **`proxy_pass` 的 URI 部分完全不展开变量**，只做前缀替换。现在若 URI 含 `$`
   就按请求展开（`upstream_target` 收 `ServerVars`）。

顺带：`proxy::fetch`（HTTP/2 / HTTP/3 / SSI / auth 子请求用）现在收 `custom`，
这几条路径也能看到捕获与 `set` 变量。

### background update 之前是 fire-and-forget

代码注释写着「caller must await the handle」，调用点却是 `drop(pending_update)`。
于是刷新任务和客户端赛跑，紧随其后的请求仍拿到 STALE。改成写完缓存体后等待句柄
（nginx 在 finalize 前等子请求），`X-Cache-Status` 的 STALE→HIT 序列才成立。

结果：`proxy_cache_use_stale.t` 27/36 → **29/36**。剩余 7 条都卡在 UPDATING
语义（另一个刷新在途时的事件位、`use_stale updating` 与 `stale-while-revalidate`
叠加、子请求里的 background update、`if` 里的更新），不是缓存本体的问题。

### 回归
35 个用例文件：32 个完全一致，3 个更好（`http_host` 58 vs 54、`ssi_if` 41 vs 32、
`http_headers_multi` 49 vs 48），0 个更差；断言 683 / 669。
`proxy_cache_use_stale.t` 单独计 29/36（见上）。自建差分套件 70/70，单测 101。

### 基准（同机 ABBA）
1k 0.950（447,538 vs 425,180）、64k 0.959、1m 0.959；64KB p99 30.59ms vs **2.65ms**。
