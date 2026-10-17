# ngxrs

nginx 兼容的高性能 Web 服务器（Rust 实现），目标是 **nginx 1.28 的功能对等**，并在相同配置/相同机器上跑赢 nginx 的吞吐与尾延迟。

- 配置语法、指令名、目录结构、错误页、日志格式尽量与 nginx 对齐
- 开发/验证机：V100（`ssh WZU_V100`，64 核 / 251 GB / Ubuntu 22.04），仓库路径 `/home/wzu/ngxrs`
- 本机镜像：`workspace/ngxrs`（编辑 → rsync → V100 编译/压测）

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

完整的功能对等矩阵与差距见 [COMPAT.md](COMPAT.md)。尚未实现的部分（反向代理、TLS、HTTP/2、HTTP/3、gzip、fastcgi、stream、mail、cache 等）按矩阵逐项推进。

## 设计取舍

- 线程模型：tokio 多线程 runtime + 每监听套接字多 accept 任务；静态文件走 `sendfile(2)`，避免用户态拷贝。
- 配置：自研 nginx 语法解析器（引号、转义、`${var}`、include 通配），不依赖第三方解析库；未知指令记录 warning 而不是直接失败（便于渐进兼容真实配置）。
- 语义差异会显式记在 COMPAT.md，不做"看起来兼容"的静默降级。
