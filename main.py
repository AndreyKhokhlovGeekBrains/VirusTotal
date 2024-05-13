import requests

# Set your API key
API_KEY = input("Enter your API key:\n")
ip_to_check = input("Enter an IP to check:\n")
def check_ip_reputation(ip_address):
    headers = {'X-Apikey': API_KEY}
    params = {'apikey': API_KEY, 'ip': ip_address}
    response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/' + ip_address, headers=headers, params=params)
    result = response.json()
    
    return result

result_dict = check_ip_reputation(ip_to_check) # Save the request result in the JSON format as a Python dict

# Extract relevant data
analysis_results = result_dict['data']['attributes']['last_analysis_results']

# Count positive detections
positive_detections = sum(1 for engine_result in analysis_results.values() if engine_result['result'] in ['malicious', 'suspicious'])

# Total number of engines
total_engines = len(analysis_results)

detection_rate = (positive_detections / total_engines) * 100

print("Detection rate:", detection_rate, "%")