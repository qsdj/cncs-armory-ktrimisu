# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import hashlib
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    poc_id = 'dae28fc3-fb5e-4993-bdff-0c122a95b2c6'
    name = 'WordPress 3.3.1 swfupload.swf XSS' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2012-11-09'  # 漏洞公布时间
    desc = '''
        WordPress 3.3.1 swfupload.swf 跨站脚本攻击漏洞.
    ''' # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/118009/WordPress-3.3.1-swfupload.swf-Cross-Site-Scripting.html' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'CVE-2012-3414 ' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress 3.3.1 swfupload.swf 3.3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e81894da-50bb-4e16-944b-ca47a38cb971'
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
            code, head, res, errcode, _ = hh.http(url + 'wp-includes/js/swfupload/swfupload.swf') 
            val_hash = '3a1c6cc728dddc258091a601f28a9c12'
            res_md5 = hashlib.md5(res)
            if val_hash == res_md5.hexdigest():           
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()



if __name__ == '__main__':
    Poc().run()