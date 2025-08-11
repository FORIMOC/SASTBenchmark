from src.cclocator.CVECollector import CVECollector

class CCLocator:
    def __init__(self):
        pass

    def run(self):
        cve_collector = CVECollector()
        cve_collector.fetch_cve_data_batch("2024-12-28", "2024-12-31")


cc_locator = CCLocator()
cc_locator.run()