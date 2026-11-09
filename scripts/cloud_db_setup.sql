-- RemoteMgr 云端数据库准备脚本
-- 在云数据库实例上执行对应数据库的段落；表结构由程序启动时自动创建，
-- 这里只需要建库 + 建账号。请把密码换成自己的强密码。

-- ===== MySQL 8 / MariaDB =====
-- CREATE DATABASE remotemgr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- CREATE USER 'remotemgr'@'%' IDENTIFIED BY 'CHANGE-ME-strong-password';
-- GRANT ALL PRIVILEGES ON remotemgr.* TO 'remotemgr'@'%';
-- FLUSH PRIVILEGES;
-- 连接串：
-- mysql+pymysql://remotemgr:CHANGE-ME-strong-password@CLOUD-HOST:3306/remotemgr?charset=utf8mb4
-- 注意：密码里的 @ : / ? # % 等字符要做 URL 编码。

-- ===== PostgreSQL 14+ =====
-- CREATE USER remotemgr WITH PASSWORD 'CHANGE-ME-strong-password';
-- CREATE DATABASE remotemgr OWNER remotemgr ENCODING 'UTF8';
-- GRANT ALL PRIVILEGES ON DATABASE remotemgr TO remotemgr;
-- 连接串：
-- postgresql+psycopg2://remotemgr:CHANGE-ME-strong-password@CLOUD-HOST:5432/remotemgr

-- ===== 切换步骤 =====
-- 1) 停服务：sudo systemctl stop remotemgr
-- 2) 改 ~/remotemgr/.env 里的 DATABASE_URL
-- 3) 复制旧数据（SQLite -> 云端）：
--    ~/remotemgr/venv/bin/python ~/remotemgr/server/manage.py copy-db \
--      --target 'mysql+pymysql://user:pass@host:3306/remotemgr?charset=utf8mb4'
-- 4) 启动：sudo systemctl start remotemgr
-- 5) 验证：curl http://127.0.0.1:8800/api/health

-- 安全提醒：数据库里只有 AES-GCM 密文，解密密钥是服务端本地的
-- ~/remotemgr/data/master.key（0600）。不要把这个文件上传到云数据库，
-- 并且要单独备份；密钥丢失 = 所有已存密码无法解密。
