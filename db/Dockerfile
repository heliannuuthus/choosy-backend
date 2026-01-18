FROM mysql:8.0

# 复制自定义 MySQL 配置文件
COPY my.cnf /etc/mysql/conf.d/custom.cnf

# 复制初始化脚本
COPY 00-schema.sql /docker-entrypoint-initdb.d/00-schema.sql
COPY 01-init.sql /docker-entrypoint-initdb.d/01-init.sql

# 注意：不在 Dockerfile 中设置 MYSQL_* 环境变量
# 这些变量应该在运行时通过 docker run -e 传递，确保每次启动都使用正确的值
# 如果在这里设置 ENV，会被"烘焙"到镜像中，但只在首次初始化时生效
# 如果数据卷已存在，entrypoint 不会重新创建用户，可能导致授权问题

# 暴露端口
EXPOSE 3306

# MySQL 默认启动命令
CMD ["mysqld"]
