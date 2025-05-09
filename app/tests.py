from django.test import TestCase

# Create your tests here.
import requests

url = 'https://localhost:3443/api/v1/scans/63df7206-dc79-496c-9310-4a46b6592bf5/results/26f3f9f5-7450-4d42-b48c-5373bb370d9f/vulnerabilities'
auth_headers = {
    'X-Auth': '1986ad8c0a5b3df4d7028d5f3c06e936c3c2c50f12f184ae7b96fbda009ac62a0',
    'content-type': 'application/json'
}
resp = requests.get(url=url,headers=auth_headers, verify=False).json().get('vulnerabilities')
print(resp)
