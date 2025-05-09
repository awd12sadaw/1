# -*- coding: utf-8 -*-
import logging

from app.LogUtils import logger

class AwvsUtils:
    """AWVS 工具类，封装扫描状态处理方法"""

    # 类属性初始化日志记录器
    logger = logger

    @staticmethod
    def process_scan_status(msg: dict) -> str:
        """处理扫描状态的核心逻辑 (静态方法版本)

        Args:
            msg: AWVS API返回的扫描状态字典

        Returns:
            str: 格式化后的中文状态文本

        Raises:
            ValueError: 当输入参数类型错误时抛出
        """
        # 参数类型校验
        if not isinstance(msg, dict):
            AwvsUtils.logger.error("非法参数类型，要求输入字典类型")
            raise ValueError("参数必须是字典类型")

        # 状态码映射表
        STATUS_MAPPING = {
            'completed': '已完成',
            'failed': '扫描失败',
            'aborted': '扫描终止',
            'processing': '扫描中',
            'queued': '队列中',
            'scheduled': '计划任务',
            'unknown': '状态异常'
        }

        # 防御性获取状态字段
        current_session = msg.get('current_session', {})
        raw_status = current_session.get('status', 'unknown').lower()

        # 处理未知状态码
        if raw_status not in STATUS_MAPPING:
            AwvsUtils.logger.warning(
                "检测到未定义的状态码: %s, 原始数据: %s",
                raw_status, msg
            )
            return STATUS_MAPPING['unknown']

        return STATUS_MAPPING[raw_status]
