# Distributed-Pcap-Dataset-Processing

## 指令格式

``````
/Library/Frameworks/Python.framework/Versions/3.10/bin/python3 /Users/cglin/Desktop/Distributed-Pcap-Dataset-Processing/pretrain/corpora_generation.py --pcap_path /Users/cglin/Desktop/pcap_data --corpora_dir /Users/cglin/Desktop --corpora_name a.txt
``````

## 输入文件格式

- pcap_data
  - A
    - facebook_audio1a.pcap
    - facebook_audio1b.pcap
    - facebook_audio2a.pcap

## 输出文件格式

- txt文件
- 一行一条数据（记得\n）