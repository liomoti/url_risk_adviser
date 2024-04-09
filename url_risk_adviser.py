
import os
import re
import requests
import colorama
from colorama import Fore, Style
from dotenv import load_dotenv
from datetime import datetime
from tabulate import tabulate


class URLRiskAdviser:
    is_success_initialized = True
    fetched_data = {}
    categories_blacklist = []
    api_key = None
    input_url = None
    report_data = None
    risk_level = "No Risk"
    risk_level_color = Fore.GREEN
    # Indicators
    is_risky_category_indicator = False
    is_exist_certificate_indicator = False
    is_malicious_antivirus_indicator = False
    is_suspicious_antivirus_indicator = False

    def __init__(self):
        load_dotenv()  # Load environment variables from .env file
        colorama.init()  # Initialize colorama
        if not self.load_categories():
            print("Error: Categories could not be loaded.")
            self.is_success_initialized = False

    def reset_variables(self):
        self.fetched_data = {}
        self.input_url = None
        self.report_data = None
        self.risk_level = "No Risk"
        self.risk_level_color = Fore.GREEN
        # Indicators
        self.is_risky_category_indicator = False
        self.is_exist_certificate_indicator = False
        self.is_malicious_antivirus_indicator = False
        self.is_suspicious_antivirus_indicator = False

    def load_categories(self) -> bool:
        """
        Loads categories from the "categories_blacklist.txt" file into the categories_blacklist attribute.
        :return: True if categories are loaded successfully, False otherwise.
        """
        try:
            with open("categories_blacklist.txt", "r") as file:
                for line in file:
                    category = line.strip()  # Remove leading and trailing whitespace, then append to the list
                    self.categories_blacklist.append(category.lower())
        except FileNotFoundError:
            print("Error: categories_blacklist.txt not found!")
            return False
        return True

    def fetch_data(self, user_url) -> bool:
        """
        This method is fetches data from VirusTotal API for the specified URL.
        :param user_url: The URL for which data is to be fetched.
        :return: True if data is successfully fetched; False otherwise.
        """
        print(f"Fetching data from VirusTotal about [{user_url}]...")
        # Fetch data from VirusTotal
        url = f"https://www.virustotal.com/api/v3/domains/{user_url}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            self.fetched_data = response.json()
            self.fetched_data = self.fetched_data['data']['attributes']
            if self.fetched_data:
                return True
        return False

    def validate_data(self) -> bool:
        """
        This method validates the fetched data to ensure required fields are present.
        :return: True if the fetched data is valid; False otherwise.
        """
        fields_list = ["last_analysis_stats"]
        return all(self.fetched_data.get(field) for field in fields_list)

    def main_analyze(self):
        """
        This method perform main analysis by executing various analyze functions.
        """
        self.analyze_category()
        self.analyze_certificate()
        self.analyze_antivirus_scans()
        self.analyze_risk_level()

    def analyze_risk_level(self):
        """
        This method calculates the risk level based on several indicators.
        """
        if self.is_malicious_antivirus_indicator:
            self.risk_level = "High Risk"
            self.risk_level_color = Fore.RED
        elif self.is_suspicious_antivirus_indicator or self.is_risky_category_indicator:
            self.risk_level = "Medium Risk"
            self.risk_level_color = Fore.RED
        elif not self.is_exist_certificate_indicator:
            self.risk_level = "Low Risk"
            self.risk_level_color = Fore.YELLOW

    def analyze_category(self):
        """
        This method analyze domain categories to identify risky categories.
        If any category is found in the predefined blacklist of risky categories,
        the corresponding flag is set to indicate a risky category.
        """
        if self.fetched_data.get('last_https_certificate_date', False):
            for source, category in self.fetched_data['categories'].items():
                if category.lower() in self.categories_blacklist:
                    self.is_risky_category_indicator = True
                    break  # Exit the loop and continue the program
        else:
            self.is_risky_category_indicator = True

    def analyze_certificate(self):
        """
        This method checks if the fetched data contains information about the last HTTPS certificate date.
        If such information is found, it sets the indicator for the existence of an HTTPS certificate to True.
        """
        if self.fetched_data.get('last_https_certificate_date', False):
            self.is_exist_certificate_indicator = True

    def analyze_antivirus_scans(self):
        """
        This method analyze antivirus scan results to identify malicious and suspicious indicators.
        """
        for key, value in self.fetched_data['last_analysis_stats'].items():
            if key == "malicious" and value > 0:
                self.is_malicious_antivirus_indicator = True
            if key == "suspicious" and value > 0:
                self.is_suspicious_antivirus_indicator = True

    def make_report(self):
        """
        Generate a comprehensive report based on the fetched data.
        This method constructs a report containing various details such as the detected URL,
        categories, HTTPS certificate information, antivirus scan results, and summary including the risk level.
        """
        # Convert epoch time to a datetime object
        last_analysis_date = self.fetched_data.get('last_analysis_date', False)
        last_analysis_date = datetime.utcfromtimestamp(last_analysis_date) if last_analysis_date else "Not Found"
        # Get categories
        if self.fetched_data.get('categories', False):
            categories = " / ".join(result for scan_engine, result in self.fetched_data['categories'].items())
        else:
            categories = "No data"
        # Get certificate information
        certificate_str = self.report_https_certificate()
        # Make antivirus table
        last_analysis_stats = self.fetched_data['last_analysis_stats']
        antivirus_table = [list(last_analysis_stats.keys()), list(last_analysis_stats.values())]
        # Set color for risk level

        # Make report data
        self.report_data = f"""
            {Fore.MAGENTA}------------------------------------{Fore.RESET}
                Detected URL: {Fore.YELLOW}{self.input_url}
            {Fore.MAGENTA}------------------------------------{Fore.RESET}
Categories: {categories}
        
        {Fore.MAGENTA}---------------- {Fore.YELLOW}HTTPS Certificate {Fore.MAGENTA}----------------{Fore.RESET}
{certificate_str}

        
        {Fore.MAGENTA}------------- {Fore.YELLOW}Antiviruses scan results {Fore.MAGENTA}------------{Fore.RESET}
Last analysis date: {last_analysis_date}
{tabulate(antivirus_table, headers='firstrow', tablefmt='grid')}
        
        {Fore.MAGENTA}---------------------- {Fore.YELLOW}Summary {Fore.MAGENTA}---------------------{Fore.RESET}
Risk Level: {self.risk_level_color}{self.risk_level}{Style.RESET_ALL}
"""

    def report_https_certificate(self) -> str:
        """
        This method generates a report regarding the HTTPS certificate status and its last update date.
        :return: A string containing the HTTPS certificate information.
        """
        https_certificate = self.fetched_data.get('last_https_certificate_date', False)
        if https_certificate:
            last_certificate_date = datetime.utcfromtimestamp(https_certificate)
            return f"Https certificate: Yes \nLast https certificate date: {last_certificate_date}"
        else:
            return "Https certificate: No"

    def save_api_key(self):
        """
        This method saves the API Key in the .env file.
        """
        with open(".env", "w") as file:
            file.write(f"API_KEY=\"{self.api_key}\"\n")
        print("API Key saved successfully.")

    def generate_filename(self) -> str:
        """
        This method generates a filename with timestamp for the report.
        :return: The filename.
        """
        timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        # Extract the domain.
        domain = self.input_url
        if domain.startswith('www.'):
            domain = domain[4:]  # Remove 'www.' prefix
        parts = domain.split('.')
        return f"report_{parts[0]}_{timestamp}.txt"

    def export_report_to_text(self):
        """
        This method writes the report content to a text file.
        """
        filename = f"reports/{self.generate_filename()}"
        # Remove unwanted ASCII characters (comes from colorama)
        chars_pattern = re.compile(r'\x1b\[[0-9;]*m')
        self.report_data = chars_pattern.sub('', self.report_data)
        # Export report to text file
        try:
            with open(filename, "w") as file:
                file.write(self.report_data)
            print(f"Report successfully written to {filename}")
        except IOError as e:
            print(f"Error writing to file: {e}. "
                  f"Please ensure that you have appropriate permissions and try running the script again.")

    def trigger_risk_adviser(self):
        # Regex pattern for URL validation
        url_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?$"
        print(f"\n"
              f"{Fore.MAGENTA} _   _______ _      ______ _     _       ___      _       _               \n"
              f"{Fore.MAGENTA}| | | | ___ \ |     | ___ (_)   | |     / _ \    | |     (_)              \n"
              f"{Fore.GREEN}| | | | |_/ / |     | |_/ /_ ___| | __ / /_\ \ __| |_   ___ ___  ___ _ __ \n"
              f"{Fore.GREEN}| | | |    /| |     |    /| / __| |/ / |  _  |/ _` \ \ / / / __|/ _ \ '__|\n"
              f"{Fore.BLUE}| |_| | |\ \| |____ | |\ \| \__ \   <  | | | | (_| |\ V /| \__ \  __/ |   \n"
              f"{Fore.BLUE} \___/\_| \_\_____/ \_| \_|_|___/_|\_\ \_| |_/\__,_| \_/ |_|___/\___|_|   \n")
        print(f"{Style.RESET_ALL}Welcome to URL Risk Adviser.\n")
        # Check for API-KEY
        self.api_key = os.getenv("API_KEY")
        if not self.api_key:
            self.api_key = input("API Key is missing, please provide: \n>")
            export_choice = input("Do you want to save the API Key in env file? (y/n): \n>")
            if export_choice.lower() == 'y':
                self.save_api_key()

        while True:
            self.reset_variables()
            self.input_url = input("In order to get a risk report, please enter the URL (or 'q' to quit): \n>")
            # Quite case
            if self.input_url.lower() == 'q':
                print("Exiting the program.")
                return  # Exit the function

            if re.match(url_pattern, self.input_url):
                if self.fetch_data(self.input_url) and self.validate_data():
                    self.main_analyze()  # Analyze data
                    self.make_report()  # Generate report
                    print(self.report_data)
                    export_choice = input("Do you want to export the report to a text file? (y/n): \n>")
                    if export_choice.lower() == 'y':
                        self.export_report_to_text()
                else:
                    print("Can't get information about the given URL.")
            else:
                print("Invalid URL format! [ Example for valid URL: www.example.com or example.com ]\n")


if __name__ == "__main__":
    url_risk_adviser = URLRiskAdviser()
    if url_risk_adviser.is_success_initialized:
        url_risk_adviser.trigger_risk_adviser()
    else:
        print("Error initializing URLRiskAdviser. Exiting...")
