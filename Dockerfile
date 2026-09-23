# Dockerfile — Phase 5: 多阶段构建
#
# v5 §三 5.1 落地：
#   - m5 修正：后端是 ESM（package.json "type": "module"），**无 build 步骤**，
#     直接 node backend/src/app.js 运行。计划里写的 "CommonJS" 是笔误——
#     实际 package.json 是 ESM。
#   - better-sqlite3 是 native 模块，build stage 需要 python3 make g++ 编译。
#   - vite alias @crypto 指向 ../backend/src/crypto，所以 backend/src 必须
#     在 build frontend 前已拷入镜像。
#   - 前端由 backend express.static 托管（不单独起 nginx）。
#
# 构建：docker build -t blindcash .
# 运行：docker compose up（见 docker-compose.yml）

# ── Stage 1: builder ──────────────────────────────────────────────────────
FROM node:22-bookworm AS builder

WORKDIR /app

# better-sqlite3 + bcrypt native 编译依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

# 先装后端依赖（better-sqlite3/bcrypt 编译）
COPY backend/package*.json ./backend/
RUN cd backend && npm ci

# 再装前端依赖
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm ci

# 拷全部源码（backend/src 必须在 build frontend 前已存在——vite alias
# @crypto → ../backend/src/crypto）
COPY . .

# 只 build 前端（后端 ESM 无 build 步骤）
RUN cd frontend && npm run build

# ── Stage 2: runtime ──────────────────────────────────────────────────────
FROM node:22-bookworm

WORKDIR /app

# 安装 tini 做 PID 1，处理信号转发（SIGTERM → cleanup job 优雅退出）。
RUN apt-get update && apt-get install -y --no-install-recommends tini \
  && rm -rf /var/lib/apt/lists/*

# 从 builder 拷运行时所需
COPY --from=builder /app/backend/node_modules ./backend/node_modules
COPY --from=builder /app/backend/package.json ./backend/package.json
COPY --from=builder /app/backend/src ./backend/src
COPY --from=builder /app/frontend/dist ./frontend/dist
COPY --from=builder /app/docs ./docs

# 数据持久化目录（docker-compose 挂 volume 到这里）
RUN mkdir -p /app/backend/data

ENV NODE_ENV=production
ENV PORT=4100
ENV BC_DB_PATH=/app/backend/data/blindcash.db

EXPOSE 4100

# tini 做 PID 1，SIGTERM 能正确转发给 node，触发 cleanup job 退出
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "backend/src/app.js"]
