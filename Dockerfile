# 签封目录分页审计服务 —— 仅依赖 Python 标准库（运行时无第三方包）。
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AUDIT_HOST=0.0.0.0 \
    AUDIT_PORT=8080 \
    AUDIT_DB=/data/audits.sqlite3

WORKDIR /app

# 构建检查与测试需要 pytest；同镜像用于 verify 阶段。
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

RUN mkdir -p /data
EXPOSE 8080

# 简单构建检查：所有模块可编译。
RUN python -m py_compile app/*.py scripts/*.py

# 默认启动审计服务；verify 容器以 command 覆盖。
CMD ["python", "-m", "app.server"]
