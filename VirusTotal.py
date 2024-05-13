import requests

# Set your API key
API_KEY = "YOUR_API_KEY_HERE"
def check_ip_reputation(ip_address):
    headers = {'X-Api-Key': API_KEY}
    params = {'apikey': API_KEY, 'ip': ip_address}
    response = requests.get('https://www.virustotal.com/vtapi/v2/ip-address/report', headers=headers, params=params)
    result = response.json()
    
    detection_rate = result['positives']/result['total']*100 if 'positives' in result else 0
    return detection_rate

ip_to_check = '8.8.8.8'
detection_rate = check_ip_reputation(ip_to_check)
print('Detection rate for', ip_to_check, ':', detection_rate, '%')
