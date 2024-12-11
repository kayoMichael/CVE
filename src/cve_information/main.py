import json
import pdb
import re
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from g4f.client import Client
import sys

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


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

    def fetch_cve_information(self) -> dict:
        return asyncio.run(self.__run_tasks())

    async def __fetch_data(self, url: str, headers: dict[str, str] = None, params: dict = None, data: dict = None, mapping: any = None) -> dict | tuple[any, dict]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, data=data) as response:
                    response.raise_for_status()
                    if mapping:
                        return {"id": mapping, "html": await response.text()}
                    return await response.json()
        except aiohttp.ClientError as error:
            self.errors.append(error)

    async def __run_tasks(self) -> dict:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36"
        }
        tasks = [self.__fetch_data(url=self.nist_nvd_api(cve_code=cve_code), headers=headers) for cve_code in self.cve_codes]
        self.result = await asyncio.gather(*tasks)

        is_error = len(self.errors) != 0
        if is_error:
            print("Server is most likely down or Service is temporarily suspended. Please Check a sample site like https://www.cve.org/CVERecord?id=CVE-2022-22971 to see if there are similar problems.")
            print("If the Server is running, In addition, Make sure Global Protect is in Central Canada for best result")
            print("Please also make sure the CVE codes are valid in the text file inputted.")
        return await self.__format_data(is_error)

    async def __format_data(self, errors: bool = False) -> dict:
        if errors:
            return {"statusCode": 400}
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
                    base_severity = self.find_severity(base_score)
                else:
                    nist_nvd_task.append(self.__fetch_data(url=self.get_nist_nvd_url(data.get('cveMetadata', {}).get('cveId')), mapping=data.get('cveMetadata', {}).get('cveId')))

            cwe_id = cna.get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('cweId')
            formatted_data = {
                "cve_id": data.get('cveMetadata', {}).get('cveId'),
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
                'problemTypes': {
                    'cweId': cwe_id,
                    'description': cna.get('problemTypes', [{}])[0].get('descriptions', [{}])[0].get('description'),
                    'reference': f'https://cwe.mitre.org/data/definitions/{cwe_id.split("-")[1]}.html' if cwe_id and '-' in cwe_id else None
                }
            }
            formatted_list.append(formatted_data)
        if len(nist_nvd_task) > 0:
            responses = await asyncio.gather(*nist_nvd_task)
            memo = {}
            results = list(filter(None, responses))
            for result in results:
                soup = BeautifulSoup(result.get('html'), 'html.parser')
                find = soup.find('a', id='Cvss3NistCalculatorAnchor')
                if find:
                    match = re.search(r'\d+\.?\d*', find.text)
                    if match:
                        score = match.group()
                        base_severity = self.find_severity(score)
                        memo[result.get('id')] = (score, base_severity)

            for data in formatted_list:
                cve_id = data['cve_id']
                if cve_id in memo:
                    se = data['vulnerability']['severity']
                    se['level'] = memo[cve_id][1]
                    se['baseScore'] = memo[cve_id][0]
            self.sort_vulnerabilities(formatted_list)
        return {"statusCode": 200, "data": self.sort_vulnerabilities(formatted_list)}

    @staticmethod
    async def _run_tasks(task_list):
        return await asyncio.gather(*task_list)

    @staticmethod
    def find_severity(base_score: str):
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

        return base_severity


    @staticmethod
    def sort_vulnerabilities(vulnerability_list):
        """
        Sort vulnerabilities by severity level with custom ordering:
        CRITICAL > HIGH > MEDIUM > LOW > None (or other values)

        Args:
            vulnerability_list (list): List of vulnerability dictionaries

        Returns:
            list: Sorted list of vulnerabilities
        """

        def severity_key(vuln):
            severity = vuln.get('vulnerability', {}).get('severity', {}).get('level')

            severity_order = {
                'CRITICAL': 5,
                'HIGH': 4,
                'MEDIUM': 3,
                'LOW': 2,
                None: 1
            }

            return severity_order.get(severity, 0)

        return sorted(vulnerability_list, key=severity_key, reverse=True)

    @staticmethod
    def prompt_ai(message: dict):
        client = Client()
        response = client.chat.completions.create(
            model="llama-3.1-70b",
            messages=[{"role": "user", "content": f"Tell me how to fix this CVE in less than 100 words. Here is the Information of the CVE in JSON: {message}"}],
        )
        return response.choices[0].message.content


