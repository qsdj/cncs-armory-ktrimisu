# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ACSNO_0001'  # 平台漏洞编号，留空
    name = '埃森诺网络服务质量检测系统 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-05-15'  # 漏洞公布时间
    desc = '''
        埃森诺网络服务质量检测系统 Struts2 命令执行。
        /usercfg/user_loginUI.do
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ACSNO(埃森诺)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8f26924e-f7b5-4a28-99eb-8d4693eca404'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # https://wooyun.shuimugan.com/bug/view?bug_no=113148
            hh = hackhttp.hackhttp()
            arg = self.target
            param_data = '/usercfg/user_loginUI.do'
            url = arg + param_data
            r = requests.get(url)

            if 'Useage' in r.content and 'Whoami' in r.content and 'WebPath' in r.content:
                #task_push('struts' ,url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
