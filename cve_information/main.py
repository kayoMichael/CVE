import json
import re
import asyncio
import pdb
from typing import List
import aiohttp
from bs4 import BeautifulSoup
from g4f.client import Client

class CVE:
    def __init__(self, cve_codes: list[str]):
        self.cve_codes = cve_codes
        self.responses = []
        self.errors = []
        self.result = None

    @staticmethod
    def nist_nvd_api(cve_code):
        return f"https://cveawg.mitre.org/api/cve/{cve_code}"

    @staticmethod
    def get_nist_nvd_url(cve_code):
        return f"https://nvd.nist.gov/vuln/detail/{cve_code}"

    def fetch_cve_information(self) -> List[dict]:
        return asyncio.run(self.__run_tasks())

    async def __fetch_data(self, url: str, headers: dict[str, str] = None, params: dict = None, data: dict = None, mapping: any = None) -> dict | tuple[any, dict]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, data=data) as response:
                    response.raise_for_status()
                    if mapping:
                        return mapping, await response.json()
                    return await response.json()
        except aiohttp.ClientError as error:
            self.errors.append(error)

    async def __run_tasks(self) -> list[dict]:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
        }
        tasks = [self.__fetch_data(url=self.nist_nvd_api(cve_code=cve_code), headers=headers) for cve_code in self.cve_codes]
        self.result = await asyncio.gather(*tasks)
        return await self.__format_data()


    async def __format_data(self) -> list[dict]:
        formatted_list = []
        nist_nvd_task = []
        for raw_data in self.result:
            if isinstance(raw_data, str):
                data = json.loads(raw_data)
            else:
                data = raw_data

            cna = data.get('containers', {}).get('cna', {})
            adp = data.get('containers', {}).get('adp', [{}])[0]

            text = cna.get('descriptions', [{}])[0].get('value', '')
            if '\n\n' in text:
                description, solution = text.split('\n\n', 1)
            else:
                description = text
                solution = None

            if solution is None:
                pattern = r"Users are recommended.*?issue\."
                match = re.search(pattern, text.replace('\n', ' '), re.IGNORECASE)
                if match:
                    solution = match.group(0)
                    description = description[:match.start()].strip()

            base_score = adp.get('metrics', [{}])[0].get('cvssV3_1', {}).get('baseScore')
            base_severity = adp.get('metrics', [{}])[0].get('cvssV3_1', {}).get('baseSeverity')
            if base_score is None:
                pattern = r"CVSS\s3\.1\sBase\sScore\s(\d+(\.\d+)?)"
                match = re.search(pattern, description)
                if match:
                    base_score = match.group(1)
                    if float(base_score) >= 9.0:
                        base_severity = "CRITICAL"
                    elif float(base_score) >= 7.0:
                        base_severity = "HIGH"
                    elif float(base_score) >= 4.0:
                        base_severity = "MEDIUM"
                    elif float(base_score) >= 0.1:
                        base_severity = "LOW"
                    else:
                        base_severity = "None"
                else:
                    nist_nvd_task.append(self.__fetch_data(url=self.get_nist_nvd_url(data.get('cveMetadata', {}).get('cveId')), mapping=data.get('cveMetadata', {}).get('cveId')))

            formatted_data = {
                'metadata': {
                    'id': data.get('cveMetadata', {}).get('cveId'),
                    'state': data.get('cveMetadata', {}).get('state'),
                    'datePublished': data.get('cveMetadata', {}).get('datePublished'),
                    'dateUpdated': data.get('cveMetadata', {}).get('dateUpdated')
                },
                'vulnerability': {
                    'title': cna.get('title'),
                    'description': description,
                    'solution': solution,
                    'severity': {
                        'level': base_severity,
                        'baseScore': base_score,
                        'vector': adp.get('metrics', [{}])[0].get('cvssV3_1', {}).get('vectorString')
                    }
                },
                'affected': {
                    'vendor': cna.get('affected', [{}])[0].get('vendor'),
                    'product': cna.get('affected', [{}])[0].get('product'),
                    'versions': {
                        'from': cna.get('affected', [{}])[0].get('versions', [{}])[0].get('version'),
                        'to': cna.get('affected', [{}])[0].get('versions', [{}])[0].get('lessThanOrEqual')
                    }
                },
                'references': [
                    {
                        'url': ref.get('url'),
                        'tags': ref.get('tags', [])
                    }
                    for ref in cna.get('references', [])
                ],
                'Problem Types': {
                    'cweId': cna.get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('cweId'),
                    'description': cna.get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('description'),
                }
            }
            formatted_list.append(formatted_data)
        if len(nist_nvd_task) > 0:
            results = await asyncio.gather(*nist_nvd_task)
            for result in results:
                pdb.set_trace()

        return self.sort_vulnerabilities(formatted_list)

    @staticmethod
    async def _run_tasks(task_list):
        return await asyncio.gather(*task_list)


    @staticmethod
    def sort_vulnerabilities(vulnerability_list):
        """
        Sort vulnerabilities by severity level with custom ordering:
        CRITICAL > HIGH > None (or other values)

        Args:
            vulnerability_list (list): List of vulnerability dictionaries

        Returns:
            list: Sorted list of vulnerabilities
        """

        def severity_key(vuln):
            severity = vuln.get('vulnerability', {}).get('severity', {}).get('level')

            severity_order = {
                'CRITICAL': 3,
                'HIGH': 2,
                None: 1
            }

            return severity_order.get(severity, 0)

        return sorted(vulnerability_list, key=severity_key, reverse=True)

    @staticmethod
    def prompt_ai(message: dict):
        client = Client()
        response = client.chat.completions.create(
            model="claude-3.5-sonnet",
            messages=[{"role": "user", "content": f"Tell me how to fix this CVE in less than 100 words. Here is the Information of the CVE in JSON: {message}"}],
        )
        return response.choices[0].message.content


