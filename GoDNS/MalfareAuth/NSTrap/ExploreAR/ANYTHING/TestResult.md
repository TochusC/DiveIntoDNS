| 类型  | 编号 | 功能             | 表现                     | 是否验证RRSIG |
|-------|------|------------------|--------------------------|---------------|
| A     | 1    | IPv4地址         | 被normalize移除          | ❌            |
| NS    | 2    | 名称服务器域名   | 被normalize移除          | ❌            |
| MD    | 3    |                  | --待测试（Obsolete）     | ❔            |
| MF    | 4    |                  | --待测试（Obsolete）     | ❔            |
| CNAME | 5    |                  | 被normalize移除          | ❌            |
| SOA   | 6    | 权威相关参数     | 进行DNSSEC验证           | ✅            |
| MB    | 7    |                  | --待测试（EXPERIMENTAL） | ❔            |
| MG    | 8    |                  | --待测试（EXPERIMENTAL） | ❔            |
| MR    | 9    |                  | --待测试（EXPERIMENTAL） | ❔            |
| NULL  | 10   |                  | --待测试（EXPERIMENTAL） | ❔            |
| WKS   | 11   |                  | ---待测试---             | ❔            |
| PTR   | 12   |                  | 进行验证                 | ✅            |
| HINFO | 13   |                  | ---待测试---             | ❔            |
| MINFO | 14   |                  | ---待测试---             | ❔            |
| MX    | 15   |                  | 进行验证                 | ✅            |
| TXT   | 16   |                  | 进行验证                 | ✅            |
| AAAA  | 28   | IPv6地址         | 被normalize移除          | ❌            |
| SRV   | 33   |                  | 进行验证                 | ✅            |
| OPT   | 41   |                  | --待测试（错误参数导致报错） | ❔        |
| DS    | 43   |                  | ---待测试---             | ❔            |
| RRSIG | 46   |                  | ---待测试---             | ❔            |
| NSEC  | 47   |                  | ---待测试---             | ❔            |
| DNSKEY| 48   |                  | ---待测试---             | ❔            |
| NSEC3 | 50   |                  | ---待测试---             | ❔            |
| NSEC  | 51   |                  | ---待测试---             | ❔            |
| ...   | ...  |                  |                          |               |
| URI   | 256  |                  | 进行验证                 | ✅            |

