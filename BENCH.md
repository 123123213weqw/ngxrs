# 基准测试记录

机器：V100（`ssh WZU_V100`），64 核，251 GB，Ubuntu 22.04，kernel 6.8。

基线：**nginx 1.28.0**，从源码编译到 `/home/wzu/nginx-baseline`（
`--with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_stub_status_module --with-http_gzip_static_module --with-threads`）。
本机 `/usr/bin/nginx` 是宝塔 OpenResty 构建且缺 lualib，不能作为基线。

## 方法

`bench/bench.sh` 用同一份配置模板分别启动 nginx 与 ngxrs（仅端口不同），
root 指向同一目录、同一批文件：

```
worker_processes auto;
sendfile on; tcp_nopush on; tcp_nodelay on;
keepalive_timeout 65; keepalive_requests 1000000;
access_log off;
```

wrk：`-t8 -c512 -d10s --latency`，先 3 s 预热，重复 3 次取 Requests/sec 中位数。
两端都在同一台机器、同一时刻交替测，避免机器状态漂移。

## 结果（2026-10-18，commit 见 bench/results/*.tsv）

| 场景 | nginx rps | ngxrs rps | 相对 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|
| 1 KB 静态文件 | 464,628 | 438,367 | 94.3% | 1.25 ms | 1.48 ms |
| 64 KB 静态文件 | 208,074 | 201,040 | 96.6% | 32.74 ms | 2.60 ms |
| 1 MB 静态文件 | 30,802 | 29,849 | 96.9% | 17.61 ms | 17.37 ms |

协议一致性：`tests/parity.py` 对 19 组请求（GET/HEAD/POST、304、Range、301、
404、非法 URI、HTTP/1.0、未知方法、错误版本……）逐字节比对状态行、关键头和 body，**19/19 全部一致**（仅 Location 的端口归一化后比较）。

## 这一轮做过的优化

1. 小文件（≤16 KB）把响应头和文件内容合并成一次 `write`，去掉第二个报文段；
   大文件仍走 `sendfile(2)`，并在 `tcp_nopush on` 时用 `TCP_CORK` 包住
   header+payload，避免 header 单独成包。
2. `Date` 头按秒缓存（thread-local），不再每请求 `gmtime_r` + 分配。
3. 线程模型改为每核一个 worker + 各自 `SO_REUSEPORT` 监听 + current_thread
   runtime，连接不再跨核迁移（对照实验：单 acceptor + mpsc 分发吞吐持平但
   p99 1 KB 从 1.2 ms 劣化到 2.95 ms，故未采用）。
4. 静态文件路径先 `metadata` 再 `open`，与 nginx 的 stat/open 次数一致；
   目录索引、ETag/Last-Modified 的计算与 nginx 对齐。

## 结论与下一步

- 大文件已基本追平（96–97%），且 p99 明显优于 nginx（64 KB 场景 12.6 倍）。
- 1 KB 仍有 ~6% 差距，热点在每请求的堆分配（响应头 `String`、ETag、
  Last-Modified 格式化）与 tokio 每请求 timer。下一步：把响应头渲染成
  `Vec<u8>` 直接写（零分配）、`Last-Modified` 用纯算术格式化、keepalive
  读超时改成连接级 deadline。
- 之后进入功能面：反向代理 / upstream / TLS / HTTP/2 / gzip / fastcgi / stream。
