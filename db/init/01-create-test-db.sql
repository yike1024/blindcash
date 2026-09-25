-- 01-create-test-db.sql — 本地测试库
--
-- postgres 镜像 entrypoint 会在创建 POSTGRES_DB（blindcash，dev 库）之后
-- 执行本目录下的脚本。这里补建 blindcash_test，与后端测试 helper 的
-- fallback DATABASE_URL（…/blindcash_test）以及 CI 的 POSTGRES_DB 对齐。
CREATE DATABASE blindcash_test;
