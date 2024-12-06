import re

def Count_request(log_file):
    try:
        with open(log_file, 'r') as file:
            IP_pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            IP_counter = {}
            for log in file:

                IP_match = re.search(IP_pattern, log)
                if IP_match:
                    IP_match = IP_match.group(0)
                    if IP_match not in IP_counter.keys():
                        IP_counter[IP_match] = 1
                    else:
                        IP_counter[IP_match] += 1
            if IP_counter:

                IP_counter = sorted(IP_counter.items(), key=lambda x:x[1], reverse=True)
                print(5*"-","IP Address Request Count",5*"-")
                print(f"{'IP ADDRESS':<20}{'Request Count'}")
                #print(IP_counter)
                for IP, count in IP_counter:
                    print(f"{IP:<20}{count}")
            else:
                print("IP Address not found in given logfile")
        print()
    except Exception as error:
        print(error)

def Most_fequent_endpoint(log_file):
    try:
        with open(log_file, 'r') as file:
            endpoint_pattern = r'\"[A-Z]+\s(/[^\s]*)'
            endpoint_counter = {}
            for log in file:

                endpoint_match = re.search(endpoint_pattern, log)
                #print(endpoint_match)
                if endpoint_match:
                    endpoint_match = endpoint_match.group(1)
                    if endpoint_match not in endpoint_counter:
                        endpoint_counter[endpoint_match] = 1
                    else:
                        endpoint_counter[endpoint_match] += 1
            if endpoint_counter:

                endpoint_counter = sorted(endpoint_counter.items(), key=lambda x:x[1], reverse=True)
                frequent_endpoint = endpoint_counter[0]
                print(4*'-',"Most Frequently Acessed Endpoint",4*'-')
                print(f'\t{frequent_endpoint[0]} (Acessed {frequent_endpoint[1]} Times)')
            else:
                print("No endpoint found in log file")
        print()
    except Exception as error:
        print(error)

def Detect_suspicious_activity(log_file, thershold = 10):
    IP_pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    failed_logins = {}
    failed_logins_patern = r' 401 |Invalid credentials'
    try:
        with open(log_file, 'r') as file:
            for log in file:
                if re.search(failed_logins_patern, log):
                    IP_match = re.search(IP_pattern, log)
                    if IP_match:
                        IP_match = IP_match.group(0)
                        if IP_match not in failed_logins.keys():
                            failed_logins[IP_match] = 1
                        else:
                            failed_logins[IP_match] += 1
            suspicious_IPs = {IP:count for IP, count in failed_logins.items() if count >= thershold}
            #print(suspicious_IPs)
            if suspicious_IPs:
                print(5*"-","Suspicious Activity Detected",5*"-")
                print(f"{'IP ADDRESS':<20}{'Failed Login Atempts'}")
                for ip, count in suspicious_IPs.items():
                    print(f"{ip:<20}{count}")
            else:
                print(5*"-","No Suspicious Activity Detected",5*"-")
    except Exception as error:
        print(error)
    print()


Count_request("sample.log")
Most_fequent_endpoint("sample.log")
Detect_suspicious_activity("sample.log",5)

