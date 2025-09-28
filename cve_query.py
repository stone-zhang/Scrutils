#!/usr/bin/env python3
"""
CVE漏洞信息查询脚本 - 支持CSV输出
使用NVD (National Vulnerability Database) API
"""

import requests
import json
import sys
import time
import re
import csv
import os
from datetime import datetime

def query_cve(cve_id):
    """
    查询单个CVE漏洞信息
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    try:
        # 清理CVE编号格式
        clean_cve_id = cve_id.strip().upper()
        if not clean_cve_id.startswith('CVE-'):
            clean_cve_id = f"CVE-{clean_cve_id}"
            
        response = requests.get(f"{base_url}?cveId={clean_cve_id}", timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if 'vulnerabilities' not in data or len(data['vulnerabilities']) == 0:
            print(f"未找到CVE编号: {clean_cve_id}")
            return None
            
        vuln = data['vulnerabilities'][0]['cve']
        
        # 提取关键信息
        result = {
            'id': vuln['id'],
            'description': vuln['descriptions'][0]['value'] if vuln['descriptions'] else '无描述',
            'published': vuln.get('published', '未知'),
            'last_modified': vuln.get('lastModified', '未知'),
            'cvss_version': '未知',
            'cvss_score': '未知',
            'cvss_severity': '未知',
            'cvss_vector': '未知',
            'weaknesses': [],
            'references': []
        }
        
        # 提取CVSS评分
        if 'metrics' in vuln:
            for metric_type in vuln['metrics']:
                for metric in vuln['metrics'][metric_type]:
                    cvss_data = metric.get('cvssData', {})
                    result['cvss_version'] = cvss_data.get('version', '未知')
                    result['cvss_score'] = cvss_data.get('baseScore', '未知')
                    result['cvss_severity'] = cvss_data.get('baseSeverity', '未知')
                    result['cvss_vector'] = cvss_data.get('vectorString', '未知')
                    break  # 只取第一个CVSS metric
                if result['cvss_score'] != '未知':
                    break
        
        # 提取弱点信息
        if 'weaknesses' in vuln:
            for weakness in vuln['weaknesses']:
                for desc in weakness['description']:
                    result['weaknesses'].append(desc['value'])
        
        # 提取参考链接
        if 'references' in vuln:
            for ref in vuln['references']:
                result['references'].append(ref['url'])
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"查询CVE {cve_id} 时发生网络错误: {e}")
        return None
    except Exception as e:
        print(f"处理CVE {cve_id} 时发生错误: {e}")
        return None

def display_cve_info(cve_info):
    """
    格式化显示CVE信息
    """
    if not cve_info:
        return
    
    print(f"\n{'='*80}")
    print(f"CVE编号: {cve_info['id']}")
    print(f"{'='*80}")
    print(f"描述: {cve_info['description']}")
    print(f"发布日期: {cve_info['published']}")
    print(f"最后修改: {cve_info['last_modified']}")
    
    if cve_info['cvss_score'] != '未知':
        print(f"\nCVSS评分信息:")
        print(f"  - 版本: {cve_info['cvss_version']}")
        print(f"    分数: {cve_info['cvss_score']}")
        print(f"    严重程度: {cve_info['cvss_severity']}")
        if cve_info['cvss_vector'] != '未知':
            print(f"    向量: {cve_info['cvss_vector']}")
    
    if cve_info['weaknesses']:
        print(f"\n弱点类型: {', '.join(cve_info['weaknesses'])}")
    
    if cve_info['references']:
        print(f"\n参考链接 (前3个):")
        for ref in cve_info['references'][:3]:
            print(f"  - {ref}")

def write_to_csv(cve_data_list, filename=None):
    """
    将CVE数据写入CSV文件
    """
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cve_results_{timestamp}.csv"
    
    # 确保文件扩展名是.csv
    if not filename.endswith('.csv'):
        filename += '.csv'
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'CVE_ID', 
                '描述', 
                '发布日期', 
                '最后修改日期',
                'CVSS版本',
                'CVSS分数',
                '严重程度',
                'CVSS向量',
                '弱点类型',
                '参考链接'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for cve_data in cve_data_list:
                if cve_data:  # 只写入成功查询的数据
                    # 将弱点类型和参考链接列表转换为字符串
                    weaknesses_str = '; '.join(cve_data['weaknesses']) if cve_data['weaknesses'] else '无'
                    references_str = '; '.join(cve_data['references'][:5]) if cve_data['references'] else '无'
                    
                    writer.writerow({
                        'CVE_ID': cve_data['id'],
                        '描述': cve_data['description'],
                        '发布日期': cve_data['published'],
                        '最后修改日期': cve_data['last_modified'],
                        'CVSS版本': cve_data['cvss_version'],
                        'CVSS分数': cve_data['cvss_score'],
                        '严重程度': cve_data['cvss_severity'],
                        'CVSS向量': cve_data['cvss_vector'],
                        '弱点类型': weaknesses_str,
                        '参考链接': references_str
                    })
        
        print(f"\n结果已保存到: {os.path.abspath(filename)}")
        return filename
        
    except Exception as e:
        print(f"写入CSV文件时发生错误: {e}")
        return None

def parse_cve_list(input_str):
    """
    解析逗号分隔的CVE列表
    """
    # 移除空格并分割
    cve_list = [cve.strip() for cve in input_str.split(',')]
    # 过滤空字符串
    cve_list = [cve for cve in cve_list if cve]
    return cve_list

def main():
    if len(sys.argv) < 2:
        print("CVE漏洞查询工具")
        print("=" * 50)
        print("使用方法:")
        print("  1. 直接输入CVE列表:")
        print("     python cve_query.py \"CVE-2020-14620, CVE-2021-35575, CVE-2021-2208\"")
        print("     python cve_query.py \"CVE-2020-14620, CVE-2021-35575\" -o my_results.csv")
        print("  2. 从文件读取CVE列表:")
        print("     python cve_query.py -f cve_list.txt")
        print("     python cve_query.py -f cve_list.txt -o my_results.csv")
        print("  3. 单个CVE查询:")
        print("     python cve_query.py CVE-2020-14620")
        print("\n文件格式支持:")
        print("  - 逗号分隔: CVE-2020-14620, CVE-2021-35575, CVE-2021-2208")
        print("  - 每行一个: CVE-2020-14620\\nCVE-2021-35575\\nCVE-2021-2208")
        print("\n示例数据:")
        print("  CVE-2020-14620, CVE-2021-35575, CVE-2021-2208, CVE-2020-14623")
        sys.exit(1)
    
    cve_list = []
    output_file = None
    
    # 解析参数
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-f' and i + 1 < len(sys.argv):
            # 文件输入
            try:
                with open(sys.argv[i+1], 'r', encoding='utf-8') as f:
                    file_content = f.read().strip()
                    # 尝试按逗号分割，如果失败则按行分割
                    if ',' in file_content:
                        cve_list = parse_cve_list(file_content)
                    else:
                        cve_list = [line.strip() for line in file_content.split('\n') if line.strip()]
                print(f"从文件 {sys.argv[i+1]} 读取了 {len(cve_list)} 个CVE编号")
                i += 2
            except FileNotFoundError:
                print(f"错误: 文件 {sys.argv[i+1]} 未找到")
                sys.exit(1)
            except Exception as e:
                print(f"读取文件时发生错误: {e}")
                sys.exit(1)
        elif sys.argv[i] == '-o' and i + 1 < len(sys.argv):
            # 输出文件
            output_file = sys.argv[i+1]
            i += 2
        else:
            # CVE列表
            if ',' in sys.argv[i]:
                cve_list = parse_cve_list(sys.argv[i])
                print(f"解析到 {len(cve_list)} 个CVE编号")
            else:
                cve_list.append(sys.argv[i])
            i += 1
    
    if not cve_list:
        print("错误: 未找到有效的CVE编号")
        sys.exit(1)
    
    success_count = 0
    failed_cves = []
    cve_data_list = []
    
    print(f"开始查询 {len(cve_list)} 个CVE漏洞...")
    
    for i, cve_id in enumerate(cve_list, 1):
        print(f"\n[{i}/{len(cve_list)}] 查询 {cve_id}...")
        cve_info = query_cve(cve_id)
        
        if cve_info:
            display_cve_info(cve_info)
            cve_data_list.append(cve_info)
            success_count += 1
        else:
            failed_cves.append(cve_id)
        
        # 避免请求过于频繁 (NVD API限制: 每6秒5个请求)
        if i < len(cve_list):
            time.sleep(1.2)
    
    # 写入CSV文件
    if cve_data_list:
        csv_file = write_to_csv(cve_data_list, output_file)
    
    # 输出统计信息
    print(f"\n{'='*50}")
    print("查询完成!")
    print(f"成功: {success_count}/{len(cve_list)}")
    if failed_cves:
        print(f"失败的CVE: {', '.join(failed_cves)}")
    if csv_file:
        print(f"结果文件: {csv_file}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
