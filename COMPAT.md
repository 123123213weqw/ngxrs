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

### 当前 A/B 结果（4 个用例文件）

| 用例 | nginx | ngxrs | 备注 |
|---|---|---|---|
| http_server_name.t | 22/22 | **21/22** | 仅剩 `server_name ""` 空名匹配 |
| http_method.t | 4/6 | **4/6** | 完全一致 |
| http_uri.t | 21/21 | 17/21 | 待查 |
| http_host.t | 54/62 | 42/62 | 待查 |

合计断言：nginx 101 / ngxrs 84。
