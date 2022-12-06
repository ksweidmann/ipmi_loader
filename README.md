# download_jnlp.py

download_jnlp.py is python script for download ipmi consoles from supermicro/dell/huawei/asrock servers.

## Installation

You need python 3.10+ and requests library

```bash
pip install requests
```

## Usage

```
python3 download_jnlp.py -u ${user} -p ${password} -H ${ipmi_host} > ipmi.jnlp
```
