# -*- coding: utf-8 -*-
import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler


def init_logger(name=__name__):
    """初始化日志记录器

    Args:
        name (str): 日志器名称，默认使用模块名

    Returns:
        logging.Logger: 配置好的日志记录器
    """
    # 创建日志记录器
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # 设置全局日志级别

    # 如果已经配置过处理器则直接返回
    if logger.handlers:
        return logger

    # 创建日志目录（如果不存在）
    log_dir = os.path.join(os.getcwd(), "logs")
    os.makedirs(log_dir, exist_ok=True)

    # 配置日志格式
    formatter = logging.Formatter(
        '%(asctime)s - [%(filename)s:%(lineno)d] - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 添加控制台处理器（可选）
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 按日期轮转的文件处理器
    file_handler = TimedRotatingFileHandler(
        filename=os.path.join(log_dir, 'app.log'),  # 基础文件名
        when='midnight',  # 每天午夜轮转
        interval=1,  # 每天生成一个新文件
        backupCount=7,  # 保留最近7天日志
        encoding='utf-8'
    )
    file_handler.suffix = "%Y-%m-%d.log"  # 定义文件名格式
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


# 初始化日志记录器
logger = init_logger()

# 使用示例
if __name__ == '__main__':
    logger.debug("调试信息")
    logger.info("程序启动")
    logger.warning("磁盘空间不足")
    logger.error("数据库连接失败")