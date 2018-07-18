# coding: utf-8

from enum import Enum


class VulnType(Enum):
    '''漏洞类型'''
    OTHER = 0  # 其他
    INJECTION = 1  # 注入
    XSS = 2  # xss跨站脚本攻击
    XXE = 3  # xml外部实体攻击
    FILE_UPLOAD = 4  # 任意文件上传
    FILE_OPERATION = 5  # 任意文件操作
    FILE_DOWNLOAD = 6  # 意文件下载
    FILE_TRAVERSAL = 7  # 目录遍历
    RCE = 8  # 远程命令/代码执行
    LFI = 9  # 本地文件包含
    RFI = 10  # 远程文件包含
    INFO_LEAK = 11  # 信息泄漏
    MISCONFIGURATION = 12  # 错误配置


class VulnLevel(Enum):
    '''漏洞危害等级'''
    LOW = 1  # 低
    MED = 2  # 中
    HIGH = 3  # 高
    SEVERITY = 4  # 严重


class ProductType(Enum):
    '''产品类型'''
    others = 0
    cms = 1
    os = 2
    middleware = 3
    database = 4
    device = 5
    service = 6
    service_provider = 7
