# -*- coding: utf-8 -*-


from django.db import IntegrityError
from django.utils import timezone

from app.LogUtils import logger
from app.models import AnalysisUrl


class Aynalyze:

    def update_analysis_url(self, msg):
        try:
            scan_id = msg.get('target_id')
            if not scan_id:
                logger.warning("缺失 scan_id，跳过更新")
                return

            # 提取 create_time（仅用于创建）
            create_time_value = self._parse_api_time(
                msg.get('current_session', {}).get('start_date')
            ) or timezone.now()

            # 更新字段（排除 create_time）
            update_fields = {
                'url': msg.get('target', {}).get('address', ''),
                'type': msg.get('profile_name', '未知类型'),
                'status': '已完成',
                'high': msg.get('current_session', {}).get('severity_counts', {}).get('high', 0),
                'middle': msg.get('current_session', {}).get('severity_counts', {}).get('medium', 0),
                'low': msg.get('current_session', {}).get('severity_counts', {}).get('low', 0),
            }

            # 原子操作：存在则更新，不存在则创建
            obj, created = AnalysisUrl.objects.update_or_create(
                scan_id=scan_id,
                defaults=update_fields
            )

            # 仅在创建时设置 create_time
            if created:
                obj.create_time = create_time_value
                obj.save(update_fields=['create_time'])

            logger.info(f"{'Created' if created else 'Updated'} record: {obj.url}")

        except IntegrityError as e:
            logger.error(f"唯一性约束冲突: {e}")
        except AnalysisUrl.MultipleObjectsReturned:
            logger.error(f"scan_id={scan_id} 存在重复记录，请检查数据库唯一性约束！")
        except Exception as e:
            logger.exception("数据库操作异常")



    def _parse_api_time(self, time_str):
        try:
            from django.utils import timezone
            from datetime import datetime
            import pytz
            # 直接解析带时区偏移的字符串（Python 3.7+ 原生支持）
            naive_time = datetime.fromisoformat(time_str)
            # 如果解析结果是 naive（无时区），则附加 UTC 时区
            if naive_time.tzinfo is None:
                return timezone.make_aware(naive_time, pytz.UTC)
            else:
                # 直接返回时区感知对象
                return naive_time
        except ValueError:
            # 回退到更通用的解析方法（如 dateutil）
            try:
                from dateutil.parser import isoparse
                return isoparse(time_str)
            except ImportError:
                logger.warning("请安装 dateutil 库以支持复杂时间格式解析")
                return None
        except (TypeError, ValueError):
            logger.warning(f"时间格式解析失败: {time_str}")
            return None
