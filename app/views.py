#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import random
import re
import time
from asyncio.log import logger

from bs4 import BeautifulSoup
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import Sum
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.utils import timezone
from django.utils.datetime_safe import datetime
from reportlab import rl_config
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from xhtml2pdf.default import DEFAULT_FONT

from user.models import User
from vulnerability_mining import settings
from .API.AwvsUtils import AwvsUtils
from .API.Scan import *
from .API.Target import *
from .API.Vuln import *
from .API.Group import *
from .API.Dashboard import *
from .Aynalyze import Aynalyze
from .models import Vulnerabilities, AnalysisUrl, Middleware_vuln

API_URL = 'https://127.0.0.1:3443'
API_KEY = '1986ad8c0a5b3df4d7028d5f3c06e936cb191aef2f2d642aab54fe66becc1f3c8'


def login(req):
    """
    跳转登录
    :param req:
    :return:
    """
    return render(req, 'login.html')


def register(req):
    """
    跳转注册
    :param req:
    :return:
    """
    return render(req, 'register.html')


def index(req):
    username = req.session['username']
    role = int(req.session['role'])
    total_scans = AnalysisUrl.objects.count()
    high = AnalysisUrl.objects.all().aggregate(binming=Sum("high"))['binming']
    middle = AnalysisUrl.objects.all().aggregate(binming=Sum("middle"))['binming']
    low = AnalysisUrl.objects.all().aggregate(binming=Sum("low"))['binming']

    total_user = User.objects.count()
    gaowei = Vulnerabilities.objects.filter(type='高危漏洞').all()
    gw_urls = []
    for i in gaowei:
        gw_urls.append(i.url)
    gaowei_length = len(gaowei)
    return render(req, 'index.html', locals())


def login_out(req):
    """
    注销登录
    :param req:
    :return:
    """
    del req.session['username']
    return HttpResponseRedirect('/')


def personal(req):
    username = req.session['username']
    role_id = req.session['role']
    user = User.objects.filter(name=username).first()

    return render(req, 'personal.html', locals())


def get_scans(request):
    """
    列表信息 | 模糊查询
    :param request:
    :return:
    """
    keyword = request.GET.get('name')
    page = request.GET.get("page", '')
    limit = request.GET.get("limit", '')
    role_id = request.GET.get('position', '')
    response_data = {}
    response_data['code'] = 0
    response_data['msg'] = ''
    data = []
    if keyword is None:
        results_obj = AnalysisUrl.objects.all()
    else:
        results_obj = AnalysisUrl.objects.filter(url__contains=keyword).all()
    paginator = Paginator(results_obj, limit)
    results = paginator.page(page)
    if results:
        for result in results:
            record = {
                "id": result.id,
                "url": result.url,
                "status": result.status,
                "high": result.high,
                "low": result.low,
                "middle": result.middle,
                'create_time': result.create_time.strftime('%Y-%m-%d %H:%m:%S'),
                "type": result.type,
                "scan_id": result.scan_id,
            }
            data.append(record)
        response_data['count'] = len(results_obj)
        response_data['data'] = data

    return JsonResponse(response_data)


def scans(request):
    """
    跳转用户页面
    """
    username = request.session['username']
    role = int(request.session['role'])
    user_id = request.session['user_id']
    return render(request, 'scans.html', locals())


def vulnscan(request):
    username = request.session['username']
    role = int(request.session['role'])
    user_id = request.session['user_id']
    return render(request, 'vulns.html', locals())


def get_vulns(request):
    """
       列表信息 | 模糊查询
       :param request:
       :return:
       """
    keyword = request.GET.get('name')
    page = request.GET.get("page", '')
    limit = request.GET.get("limit", '')
    role_id = request.GET.get('position', '')
    response_data = {}
    response_data['code'] = 0
    response_data['msg'] = ''
    data = []
    if keyword is None:
        results_obj = Vulnerabilities.objects.all()
    else:
        results_obj = Vulnerabilities.objects.filter(url__contains=keyword).all()
    paginator = Paginator(results_obj, limit)
    results = paginator.page(page)
    if results:
        for result in results:
            record = {
                "id": result.id,
                "url": result.url,
                "status": result.status,
                "leak_name": result.leak_name,
                "tags": result.tags,
                "scan_id": result.scan_id,
                'create_time': result.create_time.strftime('%Y-%m-%d %H:%m:%S'),
                "type": result.type,
            }
            data.append(record)
        response_data['count'] = len(results_obj)
        response_data['data'] = data

    return JsonResponse(response_data)


def add_scans(request):
    url = request.POST.get('ip')
    scan_type = request.POST.get('scan_type', 'full_scan')  # 默认全扫描
    print("add_scans url", url)
    print("scan_type", scan_type)
    t = Target(API_URL, API_KEY)
    target_id = t.add(url)
    if target_id is not None:
        s = Scan(API_URL, API_KEY)
        status_code = s.add(target_id, scan_type)
        print("add_scans", status_code)
        objects_filter = AnalysisUrl.objects.filter(url=url)
        if objects_filter is not None:
            objects_filter.update(scan_id=target_id)
        else:
            status = AnalysisUrl.objects.create(url=url, high=0, middle=0, low=0,
                                                type=scan_type, status='扫描中', scan_id=target_id)
            print("add_scans status", status, "url", url)
        if status_code == 200:
            return JsonResponse({'msg': 'ok'})

    return JsonResponse({'msg': 'error'})


def vulnscans(request):
    s = Scan(API_URL, API_KEY)
    api_data = s.get_all()  # 重命名为 api_data 避免命名混淆
    middleware_data = Middleware_vuln.objects.order_by('-time').values()  # 优化查询

    s_list = []

    # 处理中间件数据
    for idx, item in enumerate(middleware_data, start=1):
        s_list.append({
            'id': idx,
            'status': item['status'],
            'target_id': item.get('target_id'),  # 避免 None
            'target': item['url'],
            'scan_type': item['CVE_id'],  # 统一字段名
            'vuln': {
                'high': 1 if item['result'] else 0,
                'medium': 0,
                'low': 0,
                'info': 0
            },
            'plan_time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(item['time'])))
        })

    # 处理 API 数据
    for idx, msg in enumerate(api_data, start=len(s_list) + 1):
        status = AwvsUtils.process_scan_status(msg)
        url = msg.get('target', {}).get('address', '')
        print(f"url {url}, status {status}")
        s_list.append({
            'id': idx,
            'status': status,
            'target_id': msg['target_id'],
            'target': msg['target']['address'],
            'scan_type': msg["profile_name"],
            'vuln': msg['current_session']['severity_counts'],
            'plan_time': re.sub(r'T|\..*$', " ", msg['current_session']['start_date'])
        })
        # 仅处理状态为已完成的数据
        if status == '已完成':
            Aynalyze().update_analysis_url(msg)

    return render(request, 'vulnscans.html', {'data': s_list})


security_issues = {
    "TLS 1.0 enabled": "启用了TLS 1.0",  # [7](@ref)
    "TLS 1.1 enabled": "启用了TLS 1.1",  # [7](@ref)
    "Vulnerable JavaScript libraries": "存在漏洞的JavaScript库",  # [7](@ref)
    "Clickjacking: X-Frame-Options header": "点击劫持防护：X-Frame-Options标头缺失",  # [4,5,6,7](@ref)
    "Cookies with missing, inconsistent or contradictory properties": "Cookie属性缺失/不一致",  # [7](@ref)
    "Cookies without HttpOnly flag set": "Cookie未设置HttpOnly标志",  # [7,13](@ref)
    "Cookies without Secure flag set": "Cookie未设置Secure标志",  # [7,11,12](@ref)
    "Session cookies scoped to parent domain": "会话Cookie作用域过广",  # [7](@ref)
    "Content Security Policy (CSP) not implemented": "未实施内容安全策略(CSP)",  # [7,8,9,10](@ref)
    "HTTP Strict Transport Security (HSTS) not following best practices": "HSTS未遵循最佳实践",  # [7,11,12,13](@ref)
    "Permissions-Policy header not implemented": "未实施Permissions-Policy标头",  # [7](@ref)
    "Subresource Integrity (SRI) not implemented": "未实施子资源完整性(SRI)"  # [7](@ref)
}


def vuln_result(request, target_id):
    d = Vuln(API_URL, API_KEY)
    data = []
    vuln_details = json.loads(d.search(None, None, "open", target_id=str(target_id)))
    id = 1
    print("vuln_result")
    for target in vuln_details['vulnerabilities']:
        # translator = Translator(to_lang="chinese")
        # translation = translator.translate(target['vt_name'])
        vt_name_ = target['vt_name']
        print(vt_name_)
        print('target', target)
        translation = security_issues.get(vt_name_, vt_name_)
        if target['severity'] == 3:
            severity = '高危漏洞'
        elif target['severity'] == 2:
            severity = '中危漏洞'
        elif target['severity'] == 1:
            severity = '低危漏洞'
        else:
            severity = '无风险'
            # 获取 scan_session_id，如果字段不存在则默认 None
        vt_id = target.get('vt_id', None)
        print("vt_id=", vt_id)
        item = {
            'id': id,
            'severity': severity,
            'target': target['affects_url'],
            'vuln_id': target['vuln_id'],
            'target_id': target['target_id'],
            'session_id': vt_id,
            'vuln_name': translation,
            'time': re.sub(r'T|\..*$', " ", target['last_seen'])
        }
        print("target", target)
        id += 1
        data.append(item)
    return render(request, 'see_scans.html', {'data': data, 'target_id': target_id, 'now': timezone.now()})


# 假设 Vuln, API_URL, API_KEY, security_issues 已经在其他地方正确导入

import os
import re
import json
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template
from django.utils import timezone
from xhtml2pdf import pisa
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab import rl_config

# 假设 settings、Vuln、API_URL、API_KEY、security_issues 已经正确导入

import os
import re
import json
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template
from django.utils import timezone
from xhtml2pdf import pisa
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab import rl_config


# 假设 Vuln、API_URL、API_KEY、security_issues、settings 均已正确导入



from django.shortcuts import render
import json

from django.shortcuts import render
from django.http import JsonResponse


def vuln_detail(request, vuln_id):
    d = Vuln(API_URL, API_KEY)
    data = d.get(vuln_id)
    print(data)
    parameter_list = BeautifulSoup(data['details'], features="html.parser").findAll('span')
    request_list = BeautifulSoup(data['details'], features="html.parser").findAll('li')
    data_dict = {
        'affects_url': data['affects_url'],
        'last_seen': re.sub(r'T|\..*$', " ", data['last_seen']),
        'vt_name': data['vt_name'],
        'details': data['details'].replace("  ", '').replace('</p>', ''),
        'request': data['request'],
        'recommendation': data['recommendation'].replace('<br/>', '\n'),
        'vuln_id': vuln_id,
    }
    try:
        data_dict['parameter_name'] = parameter_list[0].contents[0]
        data_dict['parameter_data'] = parameter_list[1].contents[0]
    except:
        pass
    num = 1
    try:
        Str = ''
        for i in range(len(request_list)):
            Str += str(request_list[i].contents[0]) + str(request_list[i].contents[1]).replace('<strong>', '').replace(
                '</strong>', '') + '\n'
            num += 1
    except:
        pass
    data_dict['Tests_performed'] = Str
    data_dict['num'] = num
    data_dict['details'] = data_dict['details'].replace('class="bb-dark"', 'style="color: #ff0000"')
    return render(request, "vuln-detail.html", {'data': data_dict})

