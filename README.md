# 腾讯云APIv2版本的DDNS脚本
DDNS Python3 script of Tencent cloud APIv2.

> api doc: https://cloud.tencent.com/document/api/302/4032


## Usage

1. 请先自行在后台添加相应域名的解析记录！（因为该脚本仅仅是修改解析，没有添加解析功能）
2. 修改脚本中的SecretId、SecretKey
3. 修改脚本中的域名、子域名相关信息 `update_record()` 可多次调用
4. Exec

## Exec
`chmod 700 TencentDDns.py`  
`crontab -e`  
 `*/5 * * * * /path/to/TencentDDns.py`
