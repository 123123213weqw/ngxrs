# ngxrs

nginx 兼容的高性能 Web 服务器（Rust 实现），目标是 **nginx 1.28 的功能对等**，并在相同配置/相同机器上跑赢 nginx 的吞吐与尾延迟。

- 配置语法、指令名、目录结构、错误页、日志格式尽量与 nginx 对齐
- 所有兼容性结论都来自**同机 A/B 对照**：同一份配置分别起 nginx 与 ngxrs，逐断言/逐字节比对
- 基准机：64 核 / 251 GB / Ubuntu 22.04 单机，nginx 1.28.0 源码编译作为基线

## 构建与运行

```bash
cargo build --release
./target/release/ngxrs -t -c conf/nginx.conf      # 配置自检
./target/release/ngxrs -c conf/nginx.conf -p .    # 前台运行
curl -v http://127.0.0.1:8080/
```

## 验证

```bash
cargo test                      # 单元测试（配置词法/语法、URI、日期、Range、location 匹配）
bash bench/bench.sh             # 与 nginx 同配置压测（wrk，3 轮取中位数）
python3 tests/parity.py         # 差分测试：同一请求分别打 nginx / ngxrs，比对状态行/关键头/body
```

`tests/parity.py` 需要两个服务同时在跑：nginx 在 18080、ngxrs 在 18081，root 指向 `bench/www`。

## 当前状态

已实现（每一项都有同机 A/B 对照用例，不是"看起来能跑"）：

- **配置**：自研 nginx 语法解析（引号/转义/`${var}`/`include` 通配）、`-t` 自检、`-T` dump、`-e`/`-g`、`-s reload|stop|quit|reopen`、SIGHUP 热重载、优雅停机
- **HTTP/1.1**：keepalive、pipelining、Host 虚拟主机（精确/最长通配/尾缀/正则，完整 `server_name` 优先级）、`Expect: 100-continue`、定长与 chunked 请求体
- **静态文件**：`sendfile(2)`、ETag/Last-Modified、条件请求、Range（单段 + 多段 `multipart/byteranges`）、index、autoindex（`autoindex_format html|json|jsonp|xml`）、301、`try_files`
- **路由**：location 全优先级、`rewrite`（last/break/redirect/permanent）、`if`/`set`、`return`、`error_page`（`=code`、外部 URL、内部 location、重跑 rewrite）
- **反向代理**：`proxy_pass`（URI 前缀/变量）、`upstream`（rr/`least_conn`/`ip_hash`、weight/backup/down）、连接池 `keepalive`、WebSocket 101 双向管道、`proxy_bind`（源地址绑定）、`proxy_force_ranges`
- **缓存**：`proxy_cache`（`levels`/`keys_zone`/`max_size`/`inactive`）、`proxy_cache_valid`、Vary 变体、cache lock、`proxy_cache_revalidate`（304 → `REVALIDATED`）、`STALE`/`UPDATING`、`proxy_cookie_domain|path|flags`、`proxy_intercept_errors`
- **上游协议**：FastCGI、uwsgi、SCGI、gRPC（`grpc://` h2c、`grpcs://` TLS+ALPN、`resolver` 动态解析）
- **mail**：POP3 / IMAP / SMTP 三个协议完整实现（`auth_http`、`Auth-Method`/`Salt`、`*_auth` 按协议独立、`*_capabilities`、`starttls off|on|only` 与 `STLS`/`STARTTLS` 真实 TLS 升级、`listen ... ssl` 隐式 TLS、`smtp_greeting_delay`）
- **日志**：`error_log` 八个级别（debug…emerg）在 main/http/server/location/stream/mail 各上下文，多目的地、`stderr`、`syslog:` 走 RFC 3164
- **其它**：`gzip`、`add_header`/`add_trailer`（含 `$sent_http_*`、`$sent_trailer_*`）、`expires`、`access_log`、`allow`/`deny`/`limit_except`、`limit_req`/`limit_conn`、`map`、`geo`
- **PROXY protocol**：`listen ... proxy_protocol`（v1 与 v2 二进制，含 TLV）、`$proxy_protocol_*`、`real_ip_header proxy_protocol`、`stream` 侧 `proxy_protocol on`
- **realip**：`set_real_ip_from`（地址 / CIDR / 主机名 / `unix:`）、`real_ip_header`、`real_ip_recursive`。**peer 先受信才采信头**，`$remote_addr` 不可被任意客户端改写
- **stream 变量**：`geo`（CIDR/`ranges`/`default`/`delete`/`include`）、`map`（含正则捕获）、`set`、`split_clients`、重复 `listen`
- **WebDAV**：`dav_methods PUT DELETE MKCOL COPY MOVE`、`dav_access`、`create_full_put_path`、`min_delete_depth`，以及 `Depth`/`Overwrite`/`Destination`
- **auth**：`auth_basic`（`{PLAIN}`/`{SHA}`/`{SSHA}`/`crypt(3)`/`$apr1$`，`auth_basic_user_file` 支持变量）、`auth_request` + `auth_request_set`、`satisfy all|any`；`secure_link` 新式与老式两种签名
- **HTTP/3 (QUIC)**：`listen ... quic`，quinn + h3，请求复用同一套路由/内容管线（**QPACK 编码由 `h3` crate 决定，未与 nginx 逐位一致**）
- **TLS / HTTP2 / stream**：TLS 1.2–1.3 + SNI（精确/通配/默认回落选证）、客户端证书（`ssl_verify_client`，http 与 stream 两侧）、加密私钥（`ssl_password_file`，PKCS#8 PBES2）、ALPN `h2`（复用同一套路由表）、`stream {}` TCP/UDP 转发 + `listen ... ssl` TLS 终止 + `proxy_ssl`（上游 TLS、会话复用）

**未实现**：mail 侧客户端证书校验、`auth_request` 指向 uwsgi/SCGI 上游、`fastcgi_cache`、`slice`。

**已知差距（有实测数字，见 COMPAT.md）**：HTTP/2 帧级细节（HPACK 编码选择、连接级错误帧形状）因底层用 `h2` crate 而无法逐帧对齐，`h2.t` 116/144（nginx 144/144）、`h3_headers.t` 28/77（无 nginx 对照，本机 nginx 无 v3 模块）；1 KB 静态吞吐约 0.95× nginx，64 KB 尾延迟 p99 显著更低。
逐项兼容矩阵与已知语义差异见 [COMPAT.md](COMPAT.md)。

## 验证套件

```bash
bash bench/all.sh     # 一键跑全部自有差分套件（当前 70 项全过）
bash bench/pair.sh    # 静态/协议 19 项
bash bench/feature.sh # gzip / error_page / 代理 / 负载均衡 / WebSocket / rewrite / cache / if / auth 28 项
bash bench/tls.sh     # SNI / TLS1.2-1.3 / HTTP2 9 项
bash bench/fcgi.sh    # FastCGI / uwsgi / SCGI / stream TCP-UDP 14 项
```

每个套件都是"同一份配置起 nginx 与 ngxrs，发同一批请求，逐字节比对状态行/关键头/body"。

另外接了 nginx 官方 Perl 测试集做 A/B（`bench/nginxtests.sh`、`bench/ntscan.sh`）：
**绝对通过率没有意义**——nginx-tests master 依赖比 CPAN 更新的 `Test::Nginx`，很多用例对真 nginx 也是失败/阻塞。
这两个脚本只报"nginx 过而 ngxrs 不过"的断言，那才是真缺陷。

最近一次声明清单 A/B：**132 个文件，0 条「nginx 过而我们不过」**，
其中 127 个逐断言一致、5 个我们更多（nginx 2028 / ngxrs 2033 断言）（`http_headers_multi.t`、`proxy_cache_range.t`、`proxy_if.t`、`proxy_noclose.t`）。
范围内仍不一致的文件、缺口与复现命令逐条列在 [COMPAT.md](COMPAT.md) 第三节。

## 性能

同机、同配置、同一时间窗 ABBA 交错，`wrk -t8 -c128 -d10s`，3 轮取中位数（详见 [BENCH.md](BENCH.md)）：

| 场景 | nginx 1.28 | ngxrs | 相对 | 平均延迟 |
|---|---|---|---|---|
| 1 KB | 439,286 rps | 440,923 rps | **1.004×** | 540 µs → 380 µs |
| 64 KB | 206,988 rps | 203,886 rps | 0.985× | 39.35 ms → **703 µs** |

小文件基本持平；大文件的**平均延迟**因为我们的大文件路径没有 nginx 那样的多次拷贝而显著更低。
高并发（c≥1024）时吞吐仍略低于 nginx，差距记在 COMPAT.md 里。
