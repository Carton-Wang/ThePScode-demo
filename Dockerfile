FROM python:3.11-slim

WORKDIR /app

# Debian apt 换清华源
RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
    sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list 2>/dev/null || true

# 装根证书 + 编译工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

# 用中科大 (USTC) 镜像源安装 Rust
ENV RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
ENV RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

RUN curl --proto '=https' --tlsv1.2 -sSf \
        https://sh.rustup.rs -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --default-toolchain stable \
    && rm /tmp/rustup-init.sh

ENV PATH="/root/.cargo/bin:${PATH}"

# 配置 Cargo 使用中科大稀疏索引源
# ⚠️ 修正: 必须放在 pip install 之前, 原版放在 CMD 之后无效
RUN mkdir -p /root/.cargo && \
    printf '[source.crates-io]\nreplace-with = "ustc"\n\n[source.ustc]\nregistry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"\n' > /root/.cargo/config.toml

COPY requirements.txt .
# 用清华源安装 Python 依赖 (含新增的 cryptography)
RUN pip install --no-cache-dir \
    -i https://pypi.tuna.tsinghua.edu.cn/simple \
    --trusted-host pypi.tuna.tsinghua.edu.cn \
    -r requirements.txt

# ⚠️ 修正: 原 COPY client/ 目录不存在, 改为 demo.py
COPY src/ ./src/
COPY client/ ./client/

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# ⚠️ 新增: 份额加密落盘目录 (配合 storage.py)
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8000

CMD ["python", "-m", "src.node"]