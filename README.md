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

第一阶段：配置解析 + HTTP/1.1 keepalive + 静态文件（sendfile、ETag、Last-Modified、Range、条件请求、index、autoindex、301、try_files、return、add_header、access_log、Host 虚拟主机）。

当前实测（V100，wrk -t8 -c512 -d10s，详见 [BENCH.md](BENCH.md)）：

| 场景 | nginx 1.28 | ngxrs | 相对 |
|---|---|---|---|
| 1 KB | 464,628 rps | 438,367 rps | 94.3% |
| 64 KB | 208,074 rps | 201,040 rps | 96.6%（p99 2.60 ms vs 32.74 ms） |
| 1 MB | 30,802 rps | 29,849 rps | 96.9% |

## 验证套件

```bash
bash bench/all.sh     # 一键跑全部差分套件（当前 61 项全过）
bash bench/pair.sh    # 静态/协议 19 项
bash bench/feature.sh # gzip / error_page / 代理 / 负载均衡 / WebSocket / rewrite / cache / if 25 项
bash bench/tls.sh     # SNI / TLS1.2-1.3 / HTTP2 8 项
bash bench/fcgi.sh    # FastCGI + stream TCP/UDP 9 项
```

已实现模块：配置解析、HTTP/1.1、静态文件、rewrite/if/set、反向代理与负载均衡、
`proxy_cache`、gzip、error_page、FastCGI、`stream {}` TCP/UDP、TLS+SNI、HTTP/2。

完整的功能对等矩阵与差距见 [COMPAT.md](COMPAT.md)。尚未实现的部分（反向代理、TLS、HTTP/2、HTTP/3、gzip、fastcgi、stream、mail、cache 等）按矩阵逐项推进。

## 设计取舍

- 线程模型：每核一个 worker 线程 + 独立 `SO_REUSEPORT` 监听 + current_thread runtime（连接不跨核迁移）；静态文件走 `sendfile(2)`，≤16 KB 的响应合并成一次 write。
- 配置：自研 nginx 语法解析器（引号、转义、`${var}`、include 通配），不依赖第三方解析库；未知指令记录 warning 而不是直接失败（便于渐进兼容真实配置）。
- 语义差异会显式记在 COMPAT.md，不做"看起来兼容"的静默降级。
