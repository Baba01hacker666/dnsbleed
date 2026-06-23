import json
import csv
from colorama import Fore, Style

try:
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

def export_results(results, formats, output_base):
    if 'json' in formats:
        with open(f"{output_base}.json", "w") as f:
            json.dump(results, f, indent=2)
        print(f"Exported raw data to {output_base}.json")
        
    if 'csv' in formats:
        with open(f"{output_base}.csv", "w", newline='') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        print(f"Exported raw data to {output_base}.csv")
        
    if 'html' in formats and PLOTLY_AVAILABLE:
        success_results = [r for r in results if r['latency_ms'] is not None]
        try:
            fig = px.box(success_results, x="resolver", y="latency_ms", color="protocol", 
                         title="DNS Resolver Latency Distributions",
                         points="all")
            fig.write_html(f"{output_base}.html")
            print(f"Exported visualization to {output_base}.html")
        except Exception as e:
            print(f"{Fore.RED}[!] Could not generate HTML report: {e}{Style.RESET_ALL}")
