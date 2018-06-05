# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Zfsoft_0006' # 平台漏洞编号，留空
    name = '正方教务管理系统 文件上传漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2015-05-05'  # 漏洞公布时间
    desc = '''
        正方教务管理系统 ftb.imagegallery.aspx可上传图片，但未对图片进行重命名，可利用IIS解析漏洞1.asp;.gif方式上传脚本木马。 
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源 https://wooyun.shuimugan.com/bug/view?bug_no=6151
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '正方教务管理系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3292f3fa-98b4-492c-96aa-bc958b5955c2'
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
            code, head, res, errcode, _ = hh.http(url + '/ftb.imagegallery.aspx')
            if code == 200:
                m = re.search('not found in <b>([^<]+)</b> on line <b>(\d+)</b>', res)
                if m:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()