#!/usr/bin/env python3

import json
import os
import sys
from typing import Dict, List, Set, Any
from dataclasses import dataclass
from datetime import datetime

@dataclass
class VulnerabilityInfo:
    cve_id: str
    severity: str
    affected_packages: Set[str]
    description: str = ""
    title: str = ""

class SecurityAnalyzer:
    def __init__(self, sbom_file: str, vex_dir: str):
        self.sbom_file = sbom_file
        self.vex_dir = vex_dir
        self.sbom_packages: Set[str] = set()
        self.package_versions: Dict[str, Set[str]] = {}
    
    def _normalize_version(self, version: str) -> str:
        """標準化版本字串，移除 epoch 前綴"""
        if ':' in version:
            return version.split(':')[1]
        return version
    
    def _parse_package_name(self, full_name: str) -> tuple:
        """解析完整的套件名稱為名稱和版本"""
        parts = full_name.rsplit('-', 2)
        if len(parts) >= 2:
            name = '-'.join(parts[:-2])
            version = parts[-2]
            arch = parts[-1]
            return name, version, arch
        return full_name, "", ""

    def load_sbom(self) -> None:
        """載入並解析 SBOM 檔案"""
        try:
            with open(self.sbom_file, 'r') as f:
                sbom_data = json.load(f)
            
            if 'components' in sbom_data:
                for component in sbom_data['components']:
                    if 'name' in component:
                        name = component['name']
                        version = component.get('version', '')
                        
                        # 儲存基本套件名稱
                        self.sbom_packages.add(name)
                        
                        # 儲存完整版本資訊
                        if version:
                            version = self._normalize_version(version)
                            if name not in self.package_versions:
                                self.package_versions[name] = set()
                            self.package_versions[name].add(version)
                            
                            # 儲存完整套件名稱（包含版本）
                            full_package = f"{name}-{version}"
                            self.sbom_packages.add(full_package)
        
        except Exception as e:
            print(f"Error loading SBOM file: {e}")
            sys.exit(1)

    def _extract_package_info(self, product: Dict) -> Set[str]:
        """從產品資訊中提取套件資訊"""
        package_info = set()
        
        if 'name' in product:
            name = product['name']
            package_info.add(name)
            
            # 解析完整套件名稱
            pkg_name, pkg_version, pkg_arch = self._parse_package_name(name)
            if pkg_name and pkg_version:
                package_info.add(f"{pkg_name}-{pkg_version}")
                package_info.add(pkg_name)
        
        # 處理 PURL
        if 'product_identification_helper' in product:
            helper = product['product_identification_helper']
            if 'purl' in helper:
                package_info.add(helper['purl'])
        
        return package_info

    def _find_affected_packages(self, vex_data: Dict) -> Set[str]:
        """找出受影響的套件"""
        affected_packages = set()
        
        if 'product_tree' in vex_data and 'branches' in vex_data['product_tree']:
            def traverse_branches(branches: List[Dict]) -> None:
                for branch in branches:
                    if 'product' in branch:
                        affected_packages.update(
                            self._extract_package_info(branch['product'])
                        )
                    if 'branches' in branch:
                        traverse_branches(branch['branches'])
            
            traverse_branches(vex_data['product_tree']['branches'])
        
        return affected_packages

    def analyze_vex_files(self) -> List[VulnerabilityInfo]:
        """分析 VEX 檔案並與 SBOM 比對"""
        vulnerabilities = []
        
        for vex_file in os.listdir(self.vex_dir):
            if not vex_file.endswith('.json'):
                continue
                
            try:
                with open(os.path.join(self.vex_dir, vex_file), 'r') as f:
                    vex_data = json.load(f)
                
                doc = vex_data.get('document', {})
                
                # 提取基本資訊
                vuln_info = VulnerabilityInfo(
                    cve_id=doc['tracking'].get('id', 'Unknown'),
                    severity=doc.get('aggregate_severity', {}).get('text', 'Unknown'),
                    title=doc.get('title', ''),
                    affected_packages=self._find_affected_packages(vex_data),
                    description=''
                )
                
                # 提取描述資訊
                if 'vulnerabilities' in vex_data and vex_data['vulnerabilities']:
                    vuln = vex_data['vulnerabilities'][0]
                    for note in vuln.get('notes', []):
                        if note['category'] == 'description':
                            vuln_info.description = note['text']
                            break
                
                vulnerabilities.append(vuln_info)
                
            except Exception as e:
                print(f"Error processing VEX file {vex_file}: {e}")
                continue
        
        return vulnerabilities

    def print_results(self, vulnerabilities: List[VulnerabilityInfo]) -> None:
        """輸出分析結果"""
        for vuln in vulnerabilities:
            affected = vuln.affected_packages.intersection(self.sbom_packages)
            
            if affected:
                print("\nVulnerability Details:")
                print("=" * 50)
                print(f"CVE ID: {vuln.cve_id}")
                print(f"Impact: {vuln.severity}")
                print(f"Title: {vuln.title}")
                print("\nAffected Packages:")
                for pkg in sorted(affected):
                    # 获取版本信息
                    versions = self.package_versions.get(pkg, [])
                    version_str = ', '.join(versions) if versions else "Unknown version"
                    print(f"- {pkg} (version: {version_str})")
                if vuln.description:
                    print("\nDescription:")
                    print(vuln.description)
                print("-" * 50)

def main():
    if len(sys.argv) != 3:
        print("Usage: python security_analyzer.py <sbom_file> <vex_directory>")
        sys.exit(1)
    
    sbom_file = sys.argv[1]
    vex_dir = sys.argv[2]
    
    analyzer = SecurityAnalyzer(sbom_file, vex_dir)
    analyzer.load_sbom()
    vulnerabilities = analyzer.analyze_vex_files()
    analyzer.print_results(vulnerabilities)

if __name__ == "__main__":
    main()