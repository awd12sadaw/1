from django.db import models


class AnalysisUrl(models.Model):
    id = models.AutoField(primary_key=True)
    url = models.CharField('分析的URL地址', default='', max_length=500)
    high = models.IntegerField('高危漏洞', default=0)
    middle = models.IntegerField('中危漏洞', default=0)
    low = models.IntegerField('低危漏洞', default=0)
    type = models.CharField('扫描类型', default='', max_length=50)
    status = models.CharField('状态', default='', max_length=500)
    scan_id = models.CharField('漏洞编号', default='', max_length=500)
    create_time = models.DateTimeField('扫描时间', auto_now_add=True)

    def __str__(self):
        return self.url

    class Meta:
        db_table = 'analysis_url'


class Vulnerabilities(models.Model):
    id = models.AutoField(primary_key=True)
    url = models.CharField('具体的分析的URL地址', default='', max_length=500)
    leak_name = models.CharField('漏洞名字', default='', max_length=500)
    type = models.CharField('漏洞类别', default='低危漏洞', max_length=50)
    create_time = models.DateTimeField('扫描时间', auto_now_add=True)
    tags = models.CharField('漏洞标签', default='', max_length=255)
    status = models.CharField('漏洞状态', default='', max_length=255)
    affects_detail = models.CharField('临界细节', default='', max_length=255)
    scan_id = models.CharField('所属编号', default='', max_length=500)

    def __str__(self):
        return self.url

    class Meta:
        db_table = 'vulnerabilities'


class Middleware_vuln(models.Model):
    id = models.AutoField(primary_key=True)
    url = models.CharField(max_length=100, null=True)
    status = models.CharField(max_length=20, null=True)
    result = models.CharField(max_length=100, null=True)
    CVE_id = models.CharField(max_length=100, null=True)
    time = models.CharField(max_length=100, null=True, unique=True)
