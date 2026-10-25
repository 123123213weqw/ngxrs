# nginx 兼容矩阵

图例：`✅` 已实现并测过 · `🟡` 部分实现/有已知差异 · `⬜` 未实现

对照基线：**nginx 1.28.0**（V100 上源码编译，`$HOME/nginx-baseline/sbin/nginx`）。
所有数字都来自同一台机器上 ngxrs 与 nginx 的 **A/B 逐断言比对**，不是单边通过率。

## 一、验收判据与当前状态

判据只有一条：**「nginx 通过而 ngxrs 不通过」的断言数必须为 0**（在下方声明清单上）。
绝对通过率没有意义——nginx-tests 里的套件会因为 Test::Nginx 版本、`-V` 特性门控、
参考构建的编译选项而在两边一起失败，那种失败不构成我们的缺陷。

| 项 | 命令 | 当前结果 |
|---|---|---|
| 声明清单 A/B | `bash bench/declared.sh` | **PASS** — 76 文件，WORSE=0 TRUNC=0（nginx 1003 / ngxrs 1007 断言） |
| 自有差分套件 | `bash bench/all.sh` | **PASS** — 70/70（19 静态 + 28 功能 + 9 TLS/H2 + 14 fastcgi/uwsgi/scgi/grpc/stream） |
| 单元测试 | `cargo test --release` | **PASS** — 122 passed |
| 性能 | `CONNS=128 REPEAT=3 bash bench/abba_raw.sh` | 见 `BENCH.md`；c=128 吞吐与 64 KB 尾延迟均优于 nginx，条件见该文件 |

## 二、声明的测试清单

清单在 `bench/declared.txt`，**76 个文件**，选取规则是机械的：

1. 落在范围内（默认构建 nginx 1.28 的 http core + proxy/cache/gzip/TLS/HTTP2/
   fastcgi/uwsgi/scgi/grpc/stream/mail）；
2. **两边都真的产出了断言**——两边都跳过的套件什么也证明不了，已被排除；
3. 没有任何断言在 nginx 通过而我们失败；
4. 我方没有截断（两边断言行数相同）。

两边都不通过某些断言的套件**允许**保留：判据是「nginx 过而我们不过」，
不是绝对一致。例如 `http_keepalive.t` 两边都是 21/23，那 2 条对双方都不成立。

## 三、已知偏差（全量扫描，逐项带复现）

以下是对**全部 348 个在范围内文件**跑 A/B 的结果。共 **185 个文件 / 1733 条断言**
未对齐。每行的「复现」列是一条可直接执行的命令。

不在声明清单里的文件都在这里被列出——这份表就是「还差什么」的穷举。

### 差异总账（全量 348 文件扫描）

口径：`WORSE` = nginx 通过而 ngxrs 不通过；`TRUNC` = 我方断言行少于 nginx（跑不完）。
二者合计 **185 个文件 / 1733 条断言** 尚未对齐。

| 特性域 | 文件数 | 未对齐断言 | 主因 |
|---|---|---|---|
| stream（TCP/UDP） | 70 | 523 | 只实现了 `listen`/`proxy_pass`/`return`/TLS 终止与少量 upstream；nginx 的 179 条 stream 指令大部分缺失 |
| HTTP/2 | 28 | 361 | 帧级/HPACK 由 `h2` crate 拥有；请求体缓冲与优先级更新未实现 |
| 反向代理 | 36 | 251 | PROXY protocol、`proxy_request_buffering off`、证书缓存、`merge_headers`、`xar`/`cookie` 变量族未实现 |
| gRPC | 4 | 210 | 上游帧细节与 `next_upstream` |
| TLS | 24 | 136 | OCSP/stapling/CRL、`verify_depth`、renegotiation、证书缓存 |
| http core | 7 | 123 | `disable_symlinks`、resolver 的 AAAA/CNAME、TTL 语义 |
| upstream | 5 | 58 | `max_conns`、动态解析（`resolve`） |
| mail | 8 | 50 | TLS 会话复用、`max_errors`、PROXY protocol、resolver |
| uwsgi | 2 | 13 | SSL 证书变量 |
| FastCGI | 1 | 8 | 上游 keepalive |
| **合计** | **185** | **1733** | |

#### stream（TCP/UDP）

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `stream_upstream_service.t` | 0/23 | 23 | `TEST_LIST=stream_upstream_service.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_certificate_cache.t` | 0/22 | 22 | `TEST_LIST=stream_proxy_ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `stream_ssl_ocsp.t` | 0/22 | 22 | `TEST_LIST=stream_ssl_ocsp.t bash bench/nginxtests.sh` |
| `stream_server_name.t` | 0/21 | 21 | `TEST_LIST=stream_server_name.t bash bench/nginxtests.sh` |
| `stream_access.t` | 0/20 | 20 | `TEST_LIST=stream_access.t bash bench/nginxtests.sh` |
| `stream_geo.t` | 2/21 | 19 | `TEST_LIST=stream_geo.t bash bench/nginxtests.sh` |
| `stream_ssl_certificate_cache.t` | 0/16 | 16 | `TEST_LIST=stream_ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol2_tlv.t` | 2/16 | 14 | `TEST_LIST=stream_proxy_protocol2_tlv.t bash bench/nginxtests.sh` |
| `stream_upstream_max_conns.t` | 3/16 | 13 | `TEST_LIST=stream_upstream_max_conns.t bash bench/nginxtests.sh` |
| `stream_upstream_resolve.t` | 0/13 | 13 | `TEST_LIST=stream_upstream_resolve.t bash bench/nginxtests.sh` |
| `stream_access_log.t` | 0/12 | 12 | `TEST_LIST=stream_access_log.t bash bench/nginxtests.sh` |
| `stream_ssl_stapling.t` | 0/12 | 12 | `TEST_LIST=stream_ssl_stapling.t bash bench/nginxtests.sh` |
| `stream_limit_conn_dry_run.t` | 0/11 | 11 | `TEST_LIST=stream_limit_conn_dry_run.t bash bench/nginxtests.sh` |
| `stream_limit_rate.t` | 0/11 | 11 | `TEST_LIST=stream_limit_rate.t bash bench/nginxtests.sh` |
| `stream_limit_rate2.t` | 0/11 | 11 | `TEST_LIST=stream_limit_rate2.t bash bench/nginxtests.sh` |
| `stream_udp_limit_conn.t` | 0/11 | 11 | `TEST_LIST=stream_udp_limit_conn.t bash bench/nginxtests.sh` |
| `stream_upstream_resolve_reload.t` | 0/11 | 11 | `TEST_LIST=stream_upstream_resolve_reload.t bash bench/nginxtests.sh` |
| `stream_limit_conn.t` | 0/10 | 10 | `TEST_LIST=stream_limit_conn.t bash bench/nginxtests.sh` |
| `stream_realip.t` | 0/10 | 10 | `TEST_LIST=stream_realip.t bash bench/nginxtests.sh` |
| `stream_resolver.t` | 0/10 | 10 | `TEST_LIST=stream_resolver.t bash bench/nginxtests.sh` |
| `stream_udp_limit_rate.t` | 0/10 | 10 | `TEST_LIST=stream_udp_limit_rate.t bash bench/nginxtests.sh` |
| `stream_ssl_certificate.t` | 0/9 | 9 | `TEST_LIST=stream_ssl_certificate.t bash bench/nginxtests.sh` |
| `stream_ssl_reject_handshake.t` | 0/9 | 9 | `TEST_LIST=stream_ssl_reject_handshake.t bash bench/nginxtests.sh` |
| `stream_ssl_session_reuse.t` | 0/9 | 9 | `TEST_LIST=stream_ssl_session_reuse.t bash bench/nginxtests.sh` |
| `stream_ssl_alpn.t` | 0/8 | 8 | `TEST_LIST=stream_ssl_alpn.t bash bench/nginxtests.sh` |
| `stream_ssl_realip.t` | 0/8 | 8 | `TEST_LIST=stream_ssl_realip.t bash bench/nginxtests.sh` |
| `stream_status_variable.t` | 0/8 | 8 | `TEST_LIST=stream_status_variable.t bash bench/nginxtests.sh` |
| `stream_upstream_resolver.t` | 0/8 | 8 | `TEST_LIST=stream_upstream_resolver.t bash bench/nginxtests.sh` |
| `stream_upstream_service_reload.t` | 0/8 | 8 | `TEST_LIST=stream_upstream_service_reload.t bash bench/nginxtests.sh` |
| `stream_variables.t` | 2/10 | 8 | `TEST_LIST=stream_variables.t bash bench/nginxtests.sh` |
| `stream_proxy_complex.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_complex.t bash bench/nginxtests.sh` |
| `stream_proxy_next_upstream.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_next_upstream.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_certificate.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_ssl_certificate.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_certificate_vars.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_ssl_certificate_vars.t bash bench/nginxtests.sh` |
| `stream_geo_ipv6.t` | 2/8 | 6 | `TEST_LIST=stream_geo_ipv6.t bash bench/nginxtests.sh` |
| `stream_geo_unix.t` | 0/6 | 6 | `TEST_LIST=stream_geo_unix.t bash bench/nginxtests.sh` |
| `stream_limit_conn_complex.t` | 0/6 | 6 | `TEST_LIST=stream_limit_conn_complex.t bash bench/nginxtests.sh` |
| `stream_realip_hostname.t` | 0/6 | 6 | `TEST_LIST=stream_realip_hostname.t bash bench/nginxtests.sh` |
| `stream_ssl_sni_protocols.t` | 0/6 | 6 | `TEST_LIST=stream_ssl_sni_protocols.t bash bench/nginxtests.sh` |
| `stream_ssl_variables.t` | 2/8 | 6 | `TEST_LIST=stream_ssl_variables.t bash bench/nginxtests.sh` |
| `stream_udp_proxy_requests.t` | 22/28 | 6 | `TEST_LIST=stream_udp_proxy_requests.t bash bench/nginxtests.sh` |
| `stream_map.t` | 2/7 | 5 | `TEST_LIST=stream_map.t bash bench/nginxtests.sh` |
| `stream_ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=stream_ssl_conf_command.t bash bench/nginxtests.sh` |
| `stream_upstream.t` | 3/8 | 5 | `TEST_LIST=stream_upstream.t bash bench/nginxtests.sh` |
| `stream_proxy_half_close.t` | 0/4 | 4 | `TEST_LIST=stream_proxy_half_close.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_name.t` | 3/7 | 4 | `TEST_LIST=stream_proxy_ssl_name.t bash bench/nginxtests.sh` |
| `stream_tcp_nodelay.t` | 0/4 | 4 | `TEST_LIST=stream_tcp_nodelay.t bash bench/nginxtests.sh` |
| `stream_udp_stream.t` | 6/10 | 4 | `TEST_LIST=stream_udp_stream.t bash bench/nginxtests.sh` |
| `stream_unix.t` | 0/4 | 4 | `TEST_LIST=stream_unix.t bash bench/nginxtests.sh` |
| `stream_upstream_zone_ssl.t` | 7/11 | 4 | `TEST_LIST=stream_upstream_zone_ssl.t bash bench/nginxtests.sh` |
| `stream_proxy_bind.t` | 0/3 | 3 | `TEST_LIST=stream_proxy_bind.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_conf_command.t` | 0/3 | 3 | `TEST_LIST=stream_proxy_ssl_conf_command.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_verify.t` | 5/8 | 3 | `TEST_LIST=stream_proxy_ssl_verify.t bash bench/nginxtests.sh` |
| `stream_udp_upstream.t` | 4/7 | 3 | `TEST_LIST=stream_udp_upstream.t bash bench/nginxtests.sh` |
| `stream_upstream_random.t` | 11/14 | 3 | `TEST_LIST=stream_upstream_random.t bash bench/nginxtests.sh` |
| `stream_access_log_escape.t` | 2/4 | 2 | `TEST_LIST=stream_access_log_escape.t bash bench/nginxtests.sh` |
| `stream_geo_binary.t` | 2/4 | 2 | `TEST_LIST=stream_geo_binary.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_name_complex.t` | 2/4 | 2 | `TEST_LIST=stream_proxy_ssl_name_complex.t bash bench/nginxtests.sh` |
| `stream_set.t` | 2/4 | 2 | `TEST_LIST=stream_set.t bash bench/nginxtests.sh` |
| `stream_udp_upstream_hash.t` | 2/4 | 2 | `TEST_LIST=stream_udp_upstream_hash.t bash bench/nginxtests.sh` |
| `stream_upstream_hash.t` | 4/6 | 2 | `TEST_LIST=stream_upstream_hash.t bash bench/nginxtests.sh` |
| `stream_upstream_zone.t` | 2/4 | 2 | `TEST_LIST=stream_upstream_zone.t bash bench/nginxtests.sh` |
| `stream_access_log_none.t` | 2/3 | 1 | `TEST_LIST=stream_access_log_none.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol.t` | 3/4 | 1 | `TEST_LIST=stream_proxy_protocol.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol_ipv6.t` | 3/4 | 1 | `TEST_LIST=stream_proxy_protocol_ipv6.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol_ssl.t` | 3/4 | 1 | `TEST_LIST=stream_proxy_protocol_ssl.t bash bench/nginxtests.sh` |
| `stream_split_clients.t` | 2/3 | 1 | `TEST_LIST=stream_split_clients.t bash bench/nginxtests.sh` |
| `stream_udp_proxy.t` | 9/10 | 1 | `TEST_LIST=stream_udp_proxy.t bash bench/nginxtests.sh` |
| `stream_udp_upstream_least_conn.t` | 3/4 | 1 | `TEST_LIST=stream_udp_upstream_least_conn.t bash bench/nginxtests.sh` |
| `stream_upstream_least_conn.t` | 3/4 | 1 | `TEST_LIST=stream_upstream_least_conn.t bash bench/nginxtests.sh` |

#### HTTP/2

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `h2_priority_update.t` | 0/61 | 61 | `TEST_LIST=h2_priority_update.t bash bench/nginxtests.sh` |
| `h2_proxy_request_buffering.t` | 2/51 | 49 | `TEST_LIST=h2_proxy_request_buffering.t bash bench/nginxtests.sh` |
| `h2_fastcgi_request_buffering.t` | 2/50 | 48 | `TEST_LIST=h2_fastcgi_request_buffering.t bash bench/nginxtests.sh` |
| `h2_proxy_request_buffering_ssl.t` | 2/42 | 40 | `TEST_LIST=h2_proxy_request_buffering_ssl.t bash bench/nginxtests.sh` |
| `h2_headers.t` | 73/112 | 37 | `TEST_LIST=h2_headers.t bash bench/nginxtests.sh` |
| `h2_request_body_extra.t` | 26/52 | 26 | `TEST_LIST=h2_request_body_extra.t bash bench/nginxtests.sh` |
| `h2_absolute_redirect.t` | 7/25 | 18 | `TEST_LIST=h2_absolute_redirect.t bash bench/nginxtests.sh` |
| `h2_trailers.t` | 10/24 | 14 | `TEST_LIST=h2_trailers.t bash bench/nginxtests.sh` |
| `h2_priority.t` | 13/24 | 11 | `TEST_LIST=h2_priority.t bash bench/nginxtests.sh` |
| `h2_request_body.t` | 40/51 | 11 | `TEST_LIST=h2_request_body.t bash bench/nginxtests.sh` |
| `h2_keepalive.t` | 12/21 | 9 | `TEST_LIST=h2_keepalive.t bash bench/nginxtests.sh` |
| `h2_ssl.t` | 0/6 | 6 | `TEST_LIST=h2_ssl.t bash bench/nginxtests.sh` |
| `h2_http2.t` | 9/13 | 4 | `TEST_LIST=h2_http2.t bash bench/nginxtests.sh` |
| `h2_request_body_preread.t` | 5/11 | 4 | `TEST_LIST=h2_request_body_preread.t bash bench/nginxtests.sh` |
| `h2_ssl_variables.t` | 2/6 | 4 | `TEST_LIST=h2_ssl_variables.t bash bench/nginxtests.sh` |
| `h2_variables.t` | 4/8 | 4 | `TEST_LIST=h2_variables.t bash bench/nginxtests.sh` |
| `h2_server_tokens.t` | 11/14 | 3 | `TEST_LIST=h2_server_tokens.t bash bench/nginxtests.sh` |
| `h2_ssl_proxy_protocol.t` | 2/5 | 3 | `TEST_LIST=h2_ssl_proxy_protocol.t bash bench/nginxtests.sh` |
| `h2_ssl_verify_client.t` | 2/5 | 3 | `TEST_LIST=h2_ssl_verify_client.t bash bench/nginxtests.sh` |
| `h2_proxy_cache.t` | 9/11 | 2 | `TEST_LIST=h2_proxy_cache.t bash bench/nginxtests.sh` |
| `h2_proxy_protocol.t` | 3/5 | 2 | `TEST_LIST=h2_proxy_protocol.t bash bench/nginxtests.sh` |
| `h2_auth_request.t` | 3/4 | 1 | `TEST_LIST=h2_auth_request.t bash bench/nginxtests.sh` |
| `h2_error_page.t` | 3/4 | 1 | `TEST_LIST=h2_error_page.t bash bench/nginxtests.sh` |
| `h2_limit_conn.t` | 5/6 | 1 | `TEST_LIST=h2_limit_conn.t bash bench/nginxtests.sh` |
| `h2_limit_req.t` | 8/9 | 1 | `TEST_LIST=h2_limit_req.t bash bench/nginxtests.sh` |
| `h2_proxy_request_buffering_redirect.t` | 2/3 | 1 | `TEST_LIST=h2_proxy_request_buffering_redirect.t bash bench/nginxtests.sh` |
| `h2_proxy_ssl.t` | 2/3 | 1 | `TEST_LIST=h2_proxy_ssl.t bash bench/nginxtests.sh` |
| `h2_host.t` | 52/62 | -4 | `TEST_LIST=h2_host.t bash bench/nginxtests.sh` |

#### 反向代理

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `proxy_keepalive.t` | 15/51 | 36 | `TEST_LIST=proxy_keepalive.t bash bench/nginxtests.sh` |
| `proxy_protocol2.t` | 5/30 | 25 | `TEST_LIST=proxy_protocol2.t bash bench/nginxtests.sh` |
| `proxy_protocol.t` | 4/26 | 22 | `TEST_LIST=proxy_protocol.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate_cache.t` | 0/22 | 22 | `TEST_LIST=proxy_ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `proxy_protocol2_tlv.t` | 2/16 | 14 | `TEST_LIST=proxy_protocol2_tlv.t bash bench/nginxtests.sh` |
| `proxy_request_buffering_chunked.t` | 14/24 | 10 | `TEST_LIST=proxy_request_buffering_chunked.t bash bench/nginxtests.sh` |
| `proxy_request_buffering.t` | 11/20 | 9 | `TEST_LIST=proxy_request_buffering.t bash bench/nginxtests.sh` |
| `proxy_request_buffering_ssl.t` | 11/20 | 9 | `TEST_LIST=proxy_request_buffering_ssl.t bash bench/nginxtests.sh` |
| `proxy_merge_headers.t` | 5/13 | 8 | `TEST_LIST=proxy_merge_headers.t bash bench/nginxtests.sh` |
| `proxy_protocol_unix.t` | 0/7 | 7 | `TEST_LIST=proxy_protocol_unix.t bash bench/nginxtests.sh` |
| `proxy_unix.t` | 0/7 | 7 | `TEST_LIST=proxy_unix.t bash bench/nginxtests.sh` |
| `proxy_limit_rate2.t` | 0/6 | 6 | `TEST_LIST=proxy_limit_rate2.t bash bench/nginxtests.sh` |
| `proxy_unfinished.t` | 11/17 | 6 | `TEST_LIST=proxy_unfinished.t bash bench/nginxtests.sh` |
| `proxy_upstream_cookie.t` | 15/21 | 6 | `TEST_LIST=proxy_upstream_cookie.t bash bench/nginxtests.sh` |
| `proxy_xar.t` | 12/18 | 6 | `TEST_LIST=proxy_xar.t bash bench/nginxtests.sh` |
| `proxy_implicit.t` | 0/5 | 5 | `TEST_LIST=proxy_implicit.t bash bench/nginxtests.sh` |
| `proxy_non_idempotent.t` | 5/10 | 5 | `TEST_LIST=proxy_non_idempotent.t bash bench/nginxtests.sh` |
| `proxy_ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=proxy_ssl_conf_command.t bash bench/nginxtests.sh` |
| `proxy_upgrade.t` | 28/33 | 5 | `TEST_LIST=proxy_upgrade.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate.t` | 3/7 | 4 | `TEST_LIST=proxy_ssl_certificate.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate_vars.t` | 3/7 | 4 | `TEST_LIST=proxy_ssl_certificate_vars.t bash bench/nginxtests.sh` |
| `proxy_chunked.t` | 2/5 | 3 | `TEST_LIST=proxy_chunked.t bash bench/nginxtests.sh` |
| `proxy_method.t` | 3/6 | 3 | `TEST_LIST=proxy_method.t bash bench/nginxtests.sh` |
| `proxy_next_upstream_tries.t` | 7/10 | 3 | `TEST_LIST=proxy_next_upstream_tries.t bash bench/nginxtests.sh` |
| `proxy_pass_request.t` | 2/5 | 3 | `TEST_LIST=proxy_pass_request.t bash bench/nginxtests.sh` |
| `proxy_ssl_crl.t` | 4/7 | 3 | `TEST_LIST=proxy_ssl_crl.t bash bench/nginxtests.sh` |
| `proxy_ssl_verify.t` | 5/8 | 3 | `TEST_LIST=proxy_ssl_verify.t bash bench/nginxtests.sh` |
| `proxy_protocol_ipv6.t` | 3/5 | 2 | `TEST_LIST=proxy_protocol_ipv6.t bash bench/nginxtests.sh` |
| `proxy_set_body.t` | 2/4 | 2 | `TEST_LIST=proxy_set_body.t bash bench/nginxtests.sh` |
| `proxy_store.t` | 9/11 | 2 | `TEST_LIST=proxy_store.t bash bench/nginxtests.sh` |
| `proxy_variables.t` | 4/6 | 2 | `TEST_LIST=proxy_variables.t bash bench/nginxtests.sh` |
| `proxy_cache_lock_ssi.t` | 3/4 | 1 | `TEST_LIST=proxy_cache_lock_ssi.t bash bench/nginxtests.sh` |
| `proxy_connection_headers.t` | 4/7 | 1 | `TEST_LIST=proxy_connection_headers.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate_empty.t` | 3/4 | 1 | `TEST_LIST=proxy_ssl_certificate_empty.t bash bench/nginxtests.sh` |
| `proxy_ssl_name.t` | 10/11 | 1 | `TEST_LIST=proxy_ssl_name.t bash bench/nginxtests.sh` |
| `proxy_ssl_verify_ip.t` | 4/10 | 0 | `TEST_LIST=proxy_ssl_verify_ip.t bash bench/nginxtests.sh` |

#### gRPC

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `grpc.t` | 2/152 | 150 | `TEST_LIST=grpc.t bash bench/nginxtests.sh` |
| `grpc_ssl.t` | 2/40 | 38 | `TEST_LIST=grpc_ssl.t bash bench/nginxtests.sh` |
| `grpc_request_buffering.t` | 0/14 | 14 | `TEST_LIST=grpc_request_buffering.t bash bench/nginxtests.sh` |
| `grpc_next_upstream.t` | 3/11 | 8 | `TEST_LIST=grpc_next_upstream.t bash bench/nginxtests.sh` |

#### TLS

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `ssl_certificate_cache.t` | 0/16 | 16 | `TEST_LIST=ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `ssl_proxy_protocol.t` | 4/20 | 16 | `TEST_LIST=ssl_proxy_protocol.t bash bench/nginxtests.sh` |
| `ssl_ocsp.t` | 3/17 | 14 | `TEST_LIST=ssl_ocsp.t bash bench/nginxtests.sh` |
| `ssl_certificate.t` | 0/13 | 13 | `TEST_LIST=ssl_certificate.t bash bench/nginxtests.sh` |
| `ssl.t` | 14/23 | 9 | `TEST_LIST=ssl.t bash bench/nginxtests.sh` |
| `ssl_verify_depth.t` | 2/11 | 9 | `TEST_LIST=ssl_verify_depth.t bash bench/nginxtests.sh` |
| `ssl_sni_protocols.t` | 0/6 | 6 | `TEST_LIST=ssl_sni_protocols.t bash bench/nginxtests.sh` |
| `ssl_certificate_aux.t` | 0/5 | 5 | `TEST_LIST=ssl_certificate_aux.t bash bench/nginxtests.sh` |
| `ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=ssl_conf_command.t bash bench/nginxtests.sh` |
| `ssl_crl.t` | 2/7 | 5 | `TEST_LIST=ssl_crl.t bash bench/nginxtests.sh` |
| `ssl_password_file.t` | 0/5 | 5 | `TEST_LIST=ssl_password_file.t bash bench/nginxtests.sh` |
| `ssl_proxy_upgrade.t` | 27/32 | 5 | `TEST_LIST=ssl_proxy_upgrade.t bash bench/nginxtests.sh` |
| `ssl_stapling.t` | 7/12 | 5 | `TEST_LIST=ssl_stapling.t bash bench/nginxtests.sh` |
| `ssl_cache.t` | 2/6 | 4 | `TEST_LIST=ssl_cache.t bash bench/nginxtests.sh` |
| `ssl_sni_reneg.t` | 6/10 | 4 | `TEST_LIST=ssl_sni_reneg.t bash bench/nginxtests.sh` |
| `ssl_reject_handshake.t` | 6/9 | 3 | `TEST_LIST=ssl_reject_handshake.t bash bench/nginxtests.sh` |
| `ssl_cache_reload.t` | 5/7 | 2 | `TEST_LIST=ssl_cache_reload.t bash bench/nginxtests.sh` |
| `ssl_client_escaped_cert.t` | 3/5 | 2 | `TEST_LIST=ssl_client_escaped_cert.t bash bench/nginxtests.sh` |
| `ssl_session_reuse.t` | 8/10 | 2 | `TEST_LIST=ssl_session_reuse.t bash bench/nginxtests.sh` |
| `ssl_verify_client.t` | 14/16 | 2 | `TEST_LIST=ssl_verify_client.t bash bench/nginxtests.sh` |
| `ssl_certificates.t` | 3/4 | 1 | `TEST_LIST=ssl_certificates.t bash bench/nginxtests.sh` |
| `ssl_curve.t` | 2/3 | 1 | `TEST_LIST=ssl_curve.t bash bench/nginxtests.sh` |
| `ssl_session_ticket_key.t` | 3/4 | 1 | `TEST_LIST=ssl_session_ticket_key.t bash bench/nginxtests.sh` |
| `ssl_verify_client_trusted.t` | 4/5 | 1 | `TEST_LIST=ssl_verify_client_trusted.t bash bench/nginxtests.sh` |

#### http core

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `http_resolver_aaaa.t` | 25/74 | 49 | `TEST_LIST=http_resolver_aaaa.t bash bench/nginxtests.sh` |
| `http_disable_symlinks.t` | 0/30 | 30 | `TEST_LIST=http_disable_symlinks.t bash bench/nginxtests.sh` |
| `http_resolver.t` | 15/40 | 24 | `TEST_LIST=http_resolver.t bash bench/nginxtests.sh` |
| `http_listen.t` | 0/11 | 11 | `TEST_LIST=http_listen.t bash bench/nginxtests.sh` |
| `http_resolver_cleanup.t` | 0/3 | 3 | `TEST_LIST=http_resolver_cleanup.t bash bench/nginxtests.sh` |
| `http_resolver_cname.t` | 10/13 | 3 | `TEST_LIST=http_resolver_cname.t bash bench/nginxtests.sh` |
| `http_resolver_ipv4.t` | 2/5 | 3 | `TEST_LIST=http_resolver_ipv4.t bash bench/nginxtests.sh` |

#### upstream

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `upstream_resolve.t` | 0/20 | 20 | `TEST_LIST=upstream_resolve.t bash bench/nginxtests.sh` |
| `upstream_max_conns.t` | 0/18 | 18 | `TEST_LIST=upstream_max_conns.t bash bench/nginxtests.sh` |
| `upstream_resolve_reload.t` | 0/11 | 11 | `TEST_LIST=upstream_resolve_reload.t bash bench/nginxtests.sh` |
| `upstream_resolver.t` | 0/8 | 8 | `TEST_LIST=upstream_resolver.t bash bench/nginxtests.sh` |
| `upstream_ip_hash_ipv6.t` | 5/6 | 1 | `TEST_LIST=upstream_ip_hash_ipv6.t bash bench/nginxtests.sh` |

#### mail

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `mail_ssl.t` | 2/21 | 19 | `TEST_LIST=mail_ssl.t bash bench/nginxtests.sh` |
| `mail_imap_ssl.t` | 7/15 | 8 | `TEST_LIST=mail_imap_ssl.t bash bench/nginxtests.sh` |
| `mail_max_errors.t` | 14/20 | 6 | `TEST_LIST=mail_max_errors.t bash bench/nginxtests.sh` |
| `mail_proxy_protocol.t` | 4/10 | 6 | `TEST_LIST=mail_proxy_protocol.t bash bench/nginxtests.sh` |
| `mail_ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=mail_ssl_conf_command.t bash bench/nginxtests.sh` |
| `mail_resolver.t` | 9/13 | 3 | `TEST_LIST=mail_resolver.t bash bench/nginxtests.sh` |
| `mail_ssl_session_reuse.t` | 7/9 | 2 | `TEST_LIST=mail_ssl_session_reuse.t bash bench/nginxtests.sh` |
| `mail_proxy_smtp_auth.t` | 8/9 | 1 | `TEST_LIST=mail_proxy_smtp_auth.t bash bench/nginxtests.sh` |

#### uwsgi

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `uwsgi_ssl_certificate.t` | 0/7 | 7 | `TEST_LIST=uwsgi_ssl_certificate.t bash bench/nginxtests.sh` |
| `uwsgi_ssl_certificate_vars.t` | 0/6 | 6 | `TEST_LIST=uwsgi_ssl_certificate_vars.t bash bench/nginxtests.sh` |

#### FastCGI

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `fastcgi_keepalive.t` | 0/8 | 8 | `TEST_LIST=fastcgi_keepalive.t bash bench/nginxtests.sh` |



### `ssl_certificate_cache` 与按握手的证书变量（本轮实现）

此前 `ssl_certificate` 的变量是在**配置期**展开的，这是错的。nginx 在 SNI
回调里按**每次握手**求值，`$ssl_server_name` 只有在那一刻才有值。
`ssl_certificate $ssl_server_name.crt` 正是「按域名挂不同证书」的标准写法。

现在实现：

- 路径含 `$` 的证书不预先加载，而是在 `ResolvesServerCert::resolve` 里用
  本次握手的 SNI 名展开后读取。先用 `server_name` 选中 server，再取该 server
  的证书——顺序必须是这个，证书属于 server，不属于 socket。
- `ssl_certificate_cache off | max=N [inactive=time] [valid=time]`，
  http / server 两级，`off` 为默认（每次握手重读）。
- 证书加载失败不中断 socket（上一轮已改），只让该次握手失败并写 `error` 日志。

| 套件 | 之前 | 现在 | nginx |
|---|---|---|---|
| `ssl_certificate_cache.t` | 4/16 | **14/16** | 16/16 |
| `ssl_verify_client.t` | 12/16 | **14/16** | 16/16 |

仍未对齐的 2 条都是**淘汰策略细节**，我没有从 nginx 行为反推出它的确切模型：

- `certificate 1 evicted`（`ssl_certificate_cache.t:104`）——期望插入若干项后
  某个名字的证书**取不到**；我按「(cert,key) 计一对、LRU 淘汰」实现，则总能重读成功。
- `no cache updated`（同文件 `:117`）——`ssl_certificate_cache off` 的 server
  在文件被替换后应看到新证书，我们仍返回旧的。

### 被 `-V` 门控隐藏的 TLS 套件（本轮首次真实测量）

`Test::Nginx` 的 `has('openssl:1.0.2')` 匹配 `nginx -V` 里的
`built with OpenSSL <ver>`。ngxrs 用 rustls，不会打印那一行，于是 17 个 TLS
套件在我们这侧**直接跳过**——既不通过也不失败，等于从未测量。

`bench/tlsgate.sh` 就地给 harness 的这一个判据打补丁（退出时 `trap` 还原），
把「未知」变成「已测」。实测结果：

| 阶段 | ngxrs / nginx 断言 |
|---|---|
| 首次拆开门控 | **14 / 152** |
| 实现变量证书 + 证书加载失败非致命后 | **32 / 152** |

改善来自两处真实修复：

- **`ssl_certificate` / `ssl_certificate_key` 支持变量**（nginx 1.15.9+）。
  按 geo / map 的 `default` 分支展开；`ssl_certificate.t` 0/13 → **12/13**。
- **证书加载失败不再中断监听 socket**。nginx 会记日志继续启动，随后该 server
  的握手失败——`ssl_certificate $ssl_server_name.crt` 在配置期变量为空，
  用例正是断言「无响应」。原先我们直接整个 socket 起不来。

剩余未对齐仍很大，主要是三族真实未实现的特性：

| 族 | 未对齐 | 说明 |
|---|---|---|
| `*_certificate_cache` | 70 | `ssl_certificate_cache` 指令（证书对象缓存）未实现 |
| `*_conf_command` | 17 | `ssl_conf_command` 是 OpenSSL 专有配置通道，rustls 无对应物 |
| `*_ssl_sni_protocols` / `stream_server_name` | 7 | stream 缺 `server_name`，所以 SNI 无法分流 |

### 非测试类偏差

以下偏差没有对应的 nginx-tests 套件，或无法在本机构造 A/B 对照，单独列出。

| # | 偏差 | 影响 | 复现 |
|---|---|---|---|
| N1 | **`unknown directive` 只记 warning，不报错** | nginx 在读到未知指令时 `[emerg]` 退出；ngxrs 打一行 warning 后继续启动。配置里写错指令名的部署会"看起来起来了" | `printf 'events{worker_connections 64;}\nhttp{ bogus_directive_xyz on; server{listen 127.0.0.1:19970;} }\n' > /tmp/c.conf; ngxrs -t -c /tmp/c.conf -p /tmp` → `syntax is ok`；同一份配置 `nginx -t` → `unknown directive` |
| N2 | **HTTP/3 没有 nginx 参考基线** | 本机参考 nginx 未编译 `--with-http_v3_module`，且系统 OpenSSL 3.0.2 缺少 QUIC TLS API，所以 `h3_headers.t` 的 77 条断言只有我方一侧的数字（28/77），**不能**当作与 nginx 的一致性证据 | `$HOME/nginx-baseline/sbin/nginx -V 2>&1 \| tr ' ' '\n' \| grep -c v3` → `0` |
| N3 | **HTTP/2 非法 `:authority` / 控制字符：crate 直接重置流** | nginx 对空 authority、含 `/` 或控制字符的 authority、header 值含控制字符回 **400**；`h2` crate 在把请求交给路由之前就发 `RST_STREAM`（`GOAWAY` 对控制字符），因此我们无法回答 400。这正是 `h2_host.t` 4 条失败的原因 | 见 `bench/h2auth_probe.pl`：`perl bench/h2auth_probe.pl` → 前三行 `frames=[RST_STREAM]`、第四行 `frames=[GOAWAY]` |
| N4 | **HPACK / QPACK 表示选择由 crate 决定** | 我们不能控制 Huffman 编码、动态表索引、post-base index，所以 `h2_headers.t` 73/112、`h3_headers.t` 28/77 无法用"改我们的代码"消除 | `TEST_LIST=h2_headers.t bash bench/nginxtests.sh` |
| N5 | **14 个可选模块未实现**，`-V` 中显式声明为 `--without-`，相关套件因此跳过而不是伪装通过 | `http_dav/slice/memcached/flv/mp4/geoip/image_filter/xslt/perl/secure_link/gzip_static/userid/browser/mirror` | `ngxrs -V 2>&1 \| tr ' ' '\n' \| grep -- --without` |
| N6 | **`ssl_certificate_cache` / `ssl_conf_command` 被 `-V` 特性门控隐藏** | `Test::Nginx` 的 `has()` 匹配 `-V` 文本，这两个名字不在我们的 `-V` 里，相关套件在我们这侧直接跳过——**不是答错，是压根没跑**。`bench/tlsgate.sh` 在 `-V` 之外单独驱动这批文件（就地给 harness 打补丁，退出时还原），把「未知」变成「已测」 | `bash bench/tlsgate.sh` |
| N7 | **`suwsgi://`（uwsgi over TLS）未实现** | `uwsgi_pass suwsgi://…` 报 `invalid uwsgi_pass`，配置直接起不来 | `TEST_LIST=uwsgi_ssl_certificate.t bash bench/nginxtests.sh` |
| N8 | **stream 侧的证书变量未接 stream geo** | `ssl_certificate $one.crt` 在 `stream` 里用的是 http 的 `geo` 表，stream 的 `geo` 不参与，变量展开后为空 | `TEST_LIST=stream_ssl_certificate.t bash bench/tlsgate.sh` |

## 四、能力矩阵

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


## 五、历史记录

以下为逐轮开发记录，按时间顺序排列，保留原始测量数据以便追溯。
**其中部分结论已被后续测量推翻**（例如「64 KB p99 好 11 倍」实际上是 nginx
`sendfile` 的取舍，关掉后它也到 3 ms），标注以 `BENCH.md` 与上表为准。

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

## 本轮已知回归（均已修复，见下节）

- ~~`proxy_cache_vary.t`：手工跑 48/54~~ 已修复：53/54，与 nginx 一致（唯一失败项是
  用例自带的 TODO `normalize order`，nginx 同样失败）。当时"经 A/B 脚本判定 UNRUN"
  的挂起现象在本轮复测中未再出现（11 项 proxy 簇用例全部正常完成）。
- ~~`proxy_cache_use_stale.t`：25/36，缺 `updating`/`revalidated` 事件~~ 已实现，
  现在 36/36 与 nginx 一致。

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

## 本轮（stream 客户端证书验证、stream access_log）

### 新的功能：stream 的 ssl_verify_client

之前完全没实现，`stream_ssl_verify_client.t` 连配置都起不来。现在：

- `ssl_verify_client off|on|optional|optional_no_ca`、`ssl_client_certificate`、
  `ssl_trusted_certificate`，stream 与 stream server 两级、可继承。
- 与 http 的语义**不同**：nginx 的 stream 在握手内验证 —— `on` 是
  `SSL_VERIFY_PEER|FAIL_IF_NO_PEER_CERT`，`optional` 只要对端出示了就验证失败即断，
  `optional_no_ca` 一律放行并只在 `$ssl_client_verify` 里报告原因。
  我们用自写的 `AnchorClientVerifier` 在 rustls 里做到这一点。
- `$ssl_client_verify` / `$ssl_client_cert` 在 stream `return` 里可用。

两个必须绕开的坑：

1. **X.509 v1 证书**。测试夹具是 `openssl req -x509` 生成的 v1 自签证书，webpki
   直接 `UnsupportedCertVersion`。而 OpenSSL 接受 —— 所以「叶子证书本身就是信任锚」
   应当通过。现在先做字节相等判断，再退回 webpki。
2. **`verify_tls13_signature` 也会解析证书**，同样在 v1 上失败，导致握手以
   `certificate unknown` 结束（而 `verify_client_cert` 根本不会被调用，所以单看
   verifier 是自洽的、排查时极具误导性）。对 `BadEncoding/Other` 放宽，与 http 侧
   `PermissiveClientVerifier` 的取舍一致；链验证仍是安全边界。

### stream access_log

`access_log` 与 `log_format` 在 stream 上下文里是**被忽略的**——不是因为没实现，而是
被前面一个「接受但忽略」的 match 分支遮蔽了（Rust 分支按顺序匹配）。同一份列表里
`error_log` 也是这样被遮蔽的。移出后 `access_log` 生效，`$status` 在握手失败时是 500、
正常结束时 200，与 nginx 一致。

### 结果
| 用例 | ngxrs | nginx |
|---|---|---|
| `stream_ssl_verify_client.t` | **12/12** | 12/12 |
| `stream_ssl.t` / `stream_proxy_ssl.t` | 7/7 / 8/8 | 同 |
| `stream_error_log.t` | 36/36 | 36/36 |

36 个文件的 A/B：32 个完全一致、3 个更好、2 个更差（`proxy_cache_use_stale` 29/36、
`h2_host` 52/62），断言 824 / 813。自建差分套件 70/70，单测 101。

### 基准（同机 ABBA）
1k 0.940、64k 0.972、1m 0.962；64KB p99 28.18ms vs **2.63ms**。

## 本轮（proxy_cache_use_stale 收尾、后端条件请求、combined 格式）

`proxy_cache_use_stale.t` **29/36 → 36/36**，与 nginx 完全一致。

### 三处语义修正

1. **`proxy_cache_use_stale updating` 也覆盖「没人刷新」的过期条目**。之前只在
   `background_update && within_swr` 时返回陈旧副本，于是 `use_stale updating`
   对「过期且无刷新在途」的键仍然走前台回源，返回 500。nginx 是直接发陈旧副本
   并由这次请求自己发起更新。
2. **后台刷新必须带条件头**。`proxy_cache_revalidate on` 时刷新是条件请求，
   上游答 304 就保留已存 body、只刷新有效期；我原来发的是无条件请求，于是把
   304 变成 200 并把 body 换掉。
3. **socket-free 路径（h2/h3/SSI/auth 子请求）也要发陈旧副本**。之前只有流式路径
   支持，`h2_proxy_cache` 与 SSI 的用例因此失败。注意这里**不能 await** 刷新：
   nginx 克隆子请求做更新，不阻塞客户端响应 —— 这正是
   "stale response not blocked by background update" 检查的行为。

### 另外两个真缺陷

- **`access_log` 的 `combined` 是字面量**。内置 `combined` 格式从未被展开，日志里
  写的是字符串 `combined`（之前所有依赖日志内容的断言都在看它）。补上 nginx 的
  标准格式后 `proxy_cache_revalidate.t` 的 `not modified` 通过。
- **`Last-Modified` 只有 200/206 能存**。nginx 存缓存前会剥掉其它状态码的
  `Last-Modified`，所以只有这两种状态能条件回源；我原来对 201 也发了
  `If-Modified-Since`，`other status no revalidation` 失败。
- **缓存命中要过 `not_modified`**。条件请求命中缓存时应当 304，nginx 在头部过滤器
  里做，所以命中与回源表现一致；`h2_proxy_cache.t` 的 conditional 就是这条。

### 结果
`proxy_cache_use_stale` 36/36、`proxy_cache_revalidate` 25/25、
`h2_proxy_cache` 11/11、`proxy.t` 30/30、`proxy_cache_vary` 53/54、
`proxy_cache` 17/17 —— 均与 nginx 断言数一致。23 个文件的回归：
22 个完全一致、1 个更好（`ssi_if` 41 vs 32）、0 个更差。

## sub_filter / stub_status / split_clients / referer batch

Added in one round, each verified A/B against nginx 1.28 on the same host:

| suite | ngxrs | nginx |
|---|---|---|
| `empty_gif.t` | 6/6 | 6/6 |
| `stub_status.t` | 36/36 | 36/36 |
| `split_clients.t` | 3/3 | 3/3 |
| `referer.t` | 56/56 | 56/56 |
| `sub_filter.t` | 31/32 | 32/32 |
| `sub_filter_multi.t` | 42/44 | 44/44 |

Real bugs found on the way, all of them outside the new modules:

- **The h2c preface peek blocked every connection.** `TcpStream::peek` waits
  until the whole buffer can be filled, so a client that had not yet sent 24
  bytes was parked *before* `handle_conn` ran. Consequences: `$connections_*`
  were wrong, and an 18-byte `GET / HTTP/1.0\r\n\r\n` hung. Now a
  non-blocking `recv(MSG_PEEK|MSG_DONTWAIT)`, with a 100 ms grace only when the
  bytes seen so far are a prefix of the preface.
- **`limit_rate` was never applied.** Only the `$limit_rate` variable existed.
  Measured nginx: a 155-byte header for an empty file takes **20 s** at
  `limit_rate 15`, because the write filter throttles the whole chain, headers
  included. Implemented on the write path (and on `sendfile`, which falls back
  to a buffered copy when throttled), with a readability watch during the pacing
  sleep so a client disconnect finalises the request immediately like nginx.
- **`$connection` did not exist**, so `split_clients $connection` bucketed
  everything into the first entry.
- **`index` was not a complex value**: `index index${variant}.html` never
  expanded, so `split_clients.t` returned 403 for every request.
- **`sub_filter` matching is caseless** (nginx compares `ngx_tolower` of each
  byte) and its operands are complex values.
- **`sub_filter` merge order is own-rules-first, then inherited.** Rules chain,
  each seeing the previous one's output; with the order reversed a location's
  own rule ran on an already-rewritten body.
- `handled` in `stub_status` counts **connections**, not requests.

### Known deviations

- `sub_filter` on a `proxy_pass` response is not applied: the proxy path streams
  and the filter needs the whole body. Costs 2-3 assertions in `sub_filter.t`.
- `sub_filter` with *overlapping* patterns differs: nginx chains per-rule
  streaming state machines, this implementation applies each rule over the whole
  body in order. `sub_filter_multi.t` `partial match` and `utf8 match` fail for
  this reason.

### autoindex

Verified byte-for-byte identical to nginx 1.28 on a directory containing the
awkward names `autoindex.t` uses (`bench/aiprobe.sh` diffs both pages):

- **href** uses `NGX_ESCAPE_URI_COMPONENT`, so `:` is escaped as `%3A` and the
  entry cannot be mistaken for a URI scheme. The full escaped set was read off a
  real nginx listing by driving every printable ASCII character through it
  (`bench/aiesc.sh`) rather than assumed: space and
  `` !"#$%&'()*+,:;<=>?@[\]^`{|} `` are escaped; alphanumerics and `-._~` are not.
- **label** uses `ngx_escape_html`, which escapes only `& < > "`. An apostrophe
  is *not* escaped — the previous renderer emitted `&#39;` and was wrong.
- **width** is counted in characters when `charset` is utf-8 and in bytes
  otherwise (`entry->utf_len`); a name wider than `NGX_HTTP_AUTOINDEX_NAME_LEN`
  (50) is cut to 47 and suffixed `..>`, which then HTML-escapes to `..&gt;`.
- **directories sort first**, then names — not one flat name sort.
- the date is **GMT**: `autoindex_localtime` defaults to off.
- `charset` is now parsed instead of being accepted and ignored.

## 本轮（proxy_next_upstream 完整实现 + max_fails/fail_timeout + $upstream_addr 累加）

`proxy_next_upstream` 之前只解析不生效（在"accepted, not yet honoured"清单里），
`proxy_next_upstream.t` 6/10：看似"第二个请求成功"其实只是轮询轮到了好后端。
本轮完整实现后 **10/10，与 nginx 一致**。proxy 簇 + 自建差分套件全量复测无回归
（`bench/all.sh` 70/70）。

### 实现

- **指令解析**：`off|error|timeout|invalid_header|http_500|http_502|http_503|http_504|
  http_403|http_404|http_429|non_idempotent` 位标志；参数列表**替换**默认值
  `error timeout`（只写 `http_500` 就不再对连接错误重试）。`_tries`/`_timeout`
  同步解析并生效。
- **状态码触发**：决策点在 `exchange` 解析完响应头之后、任何字节到达客户端或
  缓存之前（对应 nginx 的 `ngx_http_upstream_test_next`）。仅当"后面还有候选
  且 tries/timeout 预算允许且方法可重放"时才放弃本次响应换下一个 peer；最后一
  个候选的响应总是照常送达（`proxy_next_upstream.t` 的 `all tried with down`
  依赖这一点）。
- **非幂等方法**：POST/LOCK/PATCH 只在带 `non_idempotent` 时才对"已发送后"的
  失败重试；连接建立失败发生在任何字节发出之前，任何方法都可重试（实测 nginx
  行为）。
- **`max_fails`/`fail_timeout`**：`server` 参数补全解析（默认 1 / 10s）。
  运行时按 (upstream, server) 记 `fails`/`checked`；`fails >= max_fails` 且距
  上次尝试不足 `fail_timeout` 的 peer 被选出局。
- **`$upstream_addr` / `$upstream_status` 累加**：`timing` 的 per-request 尝试
  列表增加 addr/status 字段，与 `*_time` 一样逗号拼接，且能活过 `error_page`
  内部跳转（`proxy_intercept_errors` + `return "$upstream_addr"` 的组合因此
  从空串变成 `addr1, addr2`）。`add_header` 与 access_log 里的引用同步改为
  累加值。

### 用真 nginx 探明的语义(`bench/next_upstream_probe.conf` 八项，ngxrs 全部对齐）

| 探针 | nginx 行为 |
|---|---|
| 500 触发的重试计失败 | 是 |
| 503 触发的重试计失败 | 是 |
| **403 触发的重试计失败** | **否** |
| **429 触发的重试计失败** | **是** |
| 成功请求清零 fails | **否**（只有 fail_timeout 到期才恢复） |
| fail_timeout 到期 | peer 回到轮转 |
| `proxy_next_upstream off` + 连接错误 | 直接 502，不转移 |
| POST + 连接被拒（默认 flags） | 重试（尚未发送任何字节） |

403 不计 / 429 计与凭记忆的直觉相反，成功不清零亦然——这组结论全部来自对
nginx 1.28 的实测，不是猜的。

### 顺带修掉的两个真缺陷

1. **backup 的候选顺序**：backup peer 从未进入候选列表（`select_order` 旧逻辑
   只在主服务器全空时才用 backup 池），状态码触发的重试到不了 backup。现在
   候选 = 轮转/排序后的可用 primaries **再拼** 可用 backups：正常流量永远先打
   primary，重试能落到 backup。第一次修复时把 backup 拼进了轮转池，RR 计数器
   会让 backup 每隔一个请求顶到首位——轮转必须只作用于 primaries。
2. **`least_conn` 平局不轮转**：稳定排序 + 固定输入顺序 = 空闲时全部流量钉死
   在第一台（`upstream_least_conn.t` `balanced` 4/4 之前不过）。现在平局按 RR
   计数器轮转，`upstream_least_conn.t` 4/4。

### 遗留（未实现，与上一致）

- `upstream_hash.t` 7/17：`hash` 指令（含 ketama `consistent`）整体未实现。
- `upstream_ip_hash.t` 被 harness 跳过：ngxrs 未向 Test::Nginx 声明 realip 模块。
- `proxy.t` 曾记录的 `$upstream_header_time` 慢响应头差异未再复现（本轮 30/30）。

## 本轮（hash 负载均衡完整实现 + return 444 + rewrite 阶段 $server_port）

`upstream_hash.t` 7/17 → **17/17，与 nginx 一致**。proxy 簇 + 自建差分套件
（70/70）+ 单元测试（122/122，含新增环构建回归测试）全量复测无回归。

### 实现（算法按 nginx 1.28 源码 `ngx_http_upstream_hash_module.c` 逐行核对）

- **指令**：`hash <复杂值> [consistent]`（`LbMethod::Hash`，不再是"接受但忽略"）。
  key 在请求时经 `ServerVars` 展开（`$arg_*` 等）。
- **CRC-32**：内置 nginx 同款 IEEE 表实现（`typed::crc32_update`），哈希映射需要
  逐字节一致，不引入新依赖。
- **plain hash**（`get_hash_peer`）：`((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH`
  的 Cache::Memcached 兼容表达式——REHASH 是重试计数的**十进制字符串**前缀，
  PREV_HASH 跨重试**累加**；peer 按 `hash % total_weight` 在**全量**（含 down）主
  服务器列表上按权重游走选定；被 tried/down/max_fails 拒绝则 rehash。
- **consistent**（ketama）：配置期建环——每 peer `weight*160` 个点，
  `crc32(host \0 port prev_hash_le32)` 链式生成，按哈希排序去重；请求时
  `crc32(key)` 二分找 `第一个 >= key哈希` 的点，失败/不可用则 `hash++` 顺延。
  host/port 拆分按 nginx 从尾部扫数字遇 `:` 切分（`unix:` 前缀特判）。
- **退化**：空 key、单主服务器、超过上限 → 轮询（`get_rr_peer`）。
- **实测映射对齐**：`bench/hashprobe` 场景（plain/consistent/带权重 共 5 组 ×
  10 key）与 nginx 1.28 **逐 key 完全一致**（含 weight=10 的环）。

### 过程中修掉的三个真缺陷

1. **候选生成的自设上限**：把 nginx"逐次 get"改成预生成完整候选列表时保留了
   每 get 20 步的上限——环上起点附近长期没有低权重点时（weight=10 的组里
   恰好第 3 个 key）生成被截断、荒谬地退到 RR 轮转。nginx 的 20 上限计的是
   *peer 尝试数*而非步数；生成上限放宽到覆盖全部主服务器（plain 100 次
   rehash / chash 走满一圈环）。
2. **`return 444`**：nginx 语义是**不发任何响应直接断连**；此前会真的发出
   444 状态行（upstream_hash.t 的 444 后端全靠它）。现在 `write_response`
   对 444 直接以断连错误返回。
3. **rewrite 阶段的 `$server_port`**：`get_var` 没有该分支、恒为空串，导致
   `if ($server_port = N)` 永假（upstream_hash.t 后端按端口返回 502 的用例
   因此全空转）。`RwVars` 增加 `server_port`，从连接的监听端口一路穿进
   `resolve_target` / `apply_rewrites_*` / `run_if`。

### 其他

- `$upstream_addr` 在"无可用 peer"（选不出候选 / 错误重试耗尽）时追加
  **upstream 组名**作为最后一项（nginx "no live upstreams" 的表现形式），
  且 502 响应现在也会应用该 location 的 `add_header`（`always` 场景）。
- 后台缓存刷新（background update）没有变量上下文，hash 上游退化为轮询
  （任何 peer 都能服务该刷新）。

### 新纳入追踪的已知缺口（非本轮回归）

- `rewrite.t` 15/25（nginx 25/25）：首次纳入 A/B 清单。失败集中在 rewrite 的
  参数追加/转义与 `error_page ... return` 组合，与 $server_port 无关（该文件
  不含此变量）。后续专项处理。
- `upstream_ip_hash.t`：仍因未向 Test::Nginx 声明 realip 模块被跳过。

## 本轮（rewrite.t 打平：rewrite 参数语义 + error_page return 状态规则）

`rewrite.t` 15/25 → **25/25，与 nginx 一致**。19 文件 A/B 全量复测：18 SAME +
1 BETTER（http_host.t 58/62 对 nginx 54/62），**零 WORSE**（ngxrs 399 断言对
nginx 395）；`bench/all.sh` 70/70、单元测试 122/122。

四类修复（行为均先经 `bench/rewrite_probe.conf` 双端实测对齐，现输出与 nginx
逐字节一致）：

1. **rewrite 替换串的参数规则**（`apply_one` 重写）：按模板首个 `?` 拆成 URI 与
   args 两部分——尾部 `?` 丢弃原参数、普通新参数以 `&` 追加原参数、无 `?` 保留
   原参数；外链 redirect 的 Location 也带参数（此前 `?c=d` 整个被丢弃）。
   落入 args 部分的捕获值按 `NGX_ESCAPE_ARGS` 转义（`%`→`%25`），URI 部分保持
   未转义形式——`/capturedup/%25?a=b` 因此得到 `args:c=/capturedup/%25&a=b`。
2. **error_page → return 的状态码规则**（1.15.4+ 语义）：错误处理器的应答若为
   ≥300，其状态**替换**原错误码（`error_page 404 /return405` → 405）；若为 2xx，
   保留原错误码、只取其 body（`error_page 405 /return204` → 405 + 空 body，
   不再画蛇添足地补内建错误页——补页只发生在没有跑过 error_page 时）。
   ≥300 且空 body 的处理器应答在补内建页时保留其原有头（`return 302 "text"`
   目标的 Location 不再丢失）。
3. **原 302 的 Location 存活**：`return 302 "text"` + `error_page 302 /...` 时，
   错误处理器（如 `return 200 "text"`）不自带 Location，则沿用原 302 的
   Location——最终 302 + `Location: text` + body `text`，与 nginx 一致。
4. **location 内 URI 被改写时忽略 proxy_pass 的 URI 部分**：`rewrite ... ;
   break; proxy_pass http://u/return204;` 按改写后的 URI（/return200）直连上游。
   `Target::Loc` 增加 `uri_rewritten` 标志（Relocate 换 location 后重新计算），
   穿透到 `upstream_target`。

顺带：`return 302 "text"` 的直连响应此前 Location 会被 `write_redirect` 丢弃
的问题同样暴露并修复。

## 本轮（expires 全语义 + 错误条目缓存的 Cache-Control 交互）

`expires` 从"已解析未生效"补齐为全语义实现，`bench/expires_probe.conf`
十种形式（off/epoch/max/相对时间/`@15h`/`@15h30m`/`modified +1h`/负时间/
代理替换）双端输出与 nginx **逐字节一致**。顺带修掉新纳入追踪的
`proxy_cache_valid.t`（12/14 → **14/14**）。A/B 18 文件 334/334 全部一致，
`bench/all.sh` 70/70，单测 122/122。

### expires

- `@time`（每日定时）：**服务器本地时区**的下一个该时刻（libm `tm_gmtoff`），
  `max-age` 为距此刻的秒数——按 UTC 算会差出时区（实测 V100 UTC+8）。
- `modified <time>`：锚定 Last-Modified（缺失回落到 now）；`+1h` 的加号前缀
  要剥掉。过期时刻 **≤ now 一律 `Cache-Control: no-cache`**（负时间因此天然
  是 no-cache，不是 max-age=0）。
- `expires modified @...`：配置期拒绝（与 nginx 同样的报错文案）。
- 上游 `Cache-Control` 是**原位替换**（代理响应里保持原位置，Expires 追加在
  末尾）；自身没有的响应按 Expires 在前、Cache-Control 在后的顺序追加。
- `expires` 是 TAKE12：`modified +1h` 以两个参数到达，需要拼接（此前只存了
  "modified"）。

### parse_time 复合时间

只认单单位（`1h`）改为 nginx 语法：单位标记按任意顺序累加（`1h30m`、
`1d 12h`），裸数字为秒。`@15h30m` 依赖此修复。

### proxy_cache_valid（存量缺陷，基线 9294b16 即失败，经二进制对照确认）

- 拦截错误（`proxy_intercept_errors` + `error_page`）写缓存时把**空的响应头**
  传给了 ttl：上游错误响应携带的 `Cache-Control: max-age=N` 被无视（nginx
  ticket #1382：错误条目的有效期应取自 max-age），`no-cache` 也没有阻止
  缓存。现在传入真实头，14/14。

### 追踪清单状态

A/B 清单现存 **19 个文件全部持平**（含本轮新增 expires 探针与
proxy_cache_valid），无任何 WORSE/BETTER/UNRUN。

## 本轮（realip 模块完整实现）

`ngx_http_realip_module` 从零实现，四个官方用例一次打平：`realip.t` 10/10、
`realip_remote_addr.t` 6/6、`realip_remote_port.t` 6/6、`upstream_ip_hash.t` 5/5
（此前被 harness 跳过——`-V` 现在声明 `--with-http_realip_module`）。
A/B 23 文件 382/382 全部一致，`bench/all.sh` 70/70，单测 122/122。

### 语义（按 nginx 1.28 源码 `ngx_http_get_forwarded_addr` 逐行核对）

- `set_real_ip_from <cidr>`（本域声明替换继承表）、`real_ip_header`（默认
  `X-Real-IP`，存小写再查——头表是精确匹配）、`real_ip_recursive`。
- X-Forwarded-For：**按接收顺序的倒序**逐个头处理；头内从右往左走，**递归标志
  同时门控头内步进与跨头迭代**（`while (recursive && p > xff)`）；当前地址不受信
  任即停，已产出则保留（DONE/DECLINED 的 found 语义）。
- 值支持 `ip\[:port\]` / `[v6]:port`（`ngx_parse_addr_port`）。
- 挂在 dispatch 的 location 解析之后（等价 nginx 的 post_read+preaccess 组合，
  per-location `real_ip_header` 因此生效），重写结果经 per-request 变量表注入，
  `add_header`/`return`/日志全链路可见。
- $remote_addr 重写后，**ip_hash 与上游选择用重写值**（proxy::handle 的 peer_ip
  改从变量取）。
- $realip_remote_addr / $realip_remote_port **无重写时回落到连接值**（nginx 同），
  有重写时保留原始连接地址/端口。

### 已知偏差（记录在案）

- allow/deny 与 limit_req/limit_conn 的 zone 键仍取连接地址（nginx 在 realip
  之后评估 ACCESS 阶段）；官方用例未覆盖，后续把 access_guard 的 peer_ip 一并
  切到变量。
- `set_real_ip_from <hostname>`（realip_hostname.t）需要运行时解析，未实现。
