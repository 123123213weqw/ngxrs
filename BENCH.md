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

## 结果（2026-10-18，第二轮）

`bench/ab.sh`：同一时刻两个服务都在跑，ABBA 交错（A B B A），每档 2 轮取中位数，
不带 `--latency`（避免客户端统计拖慢双方）。32 worker 对齐。

| 并发连接 | nginx 1.28 | ngxrs | 比值 |
|---|---|---|---|
| 128（t=24） | 636,846 | 672,818 | **1.056** |
| 1024（t=24） | 810,405 | 652,660 | 0.805 |

单 worker（`worker_processes 1`，c=64）：nginx 43,832 / ngxrs 45,288 → **1.033**。

64 KB / 1 MB 静态文件（`bench/bench.sh`，t=24 c=1024）：

| 场景 | nginx | ngxrs | 比值 | p99 |
|---|---|---|---|---|
| 64 KB | 372,749 | 357,024 | 0.958 | 28.59 ms → **6.32 ms** |
| 1 MB | 62,619 | 61,917 | 0.989 | 18.01 ms → 18.46 ms |

### TLS（`bench/tlsbench.sh`，TLS1.3，t=8 c=128，ABBA 3 轮）

| 目标 | rps | 比值 |
|---|---|---|
| nginx 1.28 | 355,795 | 1.000 |
| ngxrs | 336,679 | 0.946 |

## 测量方法上踩过的坑（重要）

1. **`ulimit -n` 必须适中。** 把 fd 上限提到 hard max（1048576）会让双方都掉速，
   而且我们掉得更多；把上限压到 1024 时，我们因 EMFILE 直接返回 500，
   wrk 会把它算成 1.0M rps 的“吞吐”——完全是假数据。现在 `bench/ab.sh`、
   `bench/bench.sh` 都会检查 `Non-2xx responses`，非 0 直接报错退出。
2. **`--latency` 会压低绝对值。** 客户端逐请求记录延迟在 800k rps 时成为瓶颈，
   吞吐对比不带 `--latency`，尾延迟单独测。
3. **这台 V100 是共享机**，别的租户在跑自己的 nginx 压测（load average 一度 30）。
   所以只能相信同一时间窗内的 A/B 比值，不能跨时段比绝对值。

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
