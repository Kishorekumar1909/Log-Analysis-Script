import re
import csv

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
                print()
                return IP_counter
            else:
                print("IP Address not found in given logfile")
                return None
            
    except Exception as error:
        print(error)

def Most_frequent_endpoint(log_file):
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
                print(4*'-',"Most Frequently Accessed Endpoint",4*'-')
                print(f'\t{frequent_endpoint[0]} (Accessed {frequent_endpoint[1]} Times)')
                print()
                return frequent_endpoint
            else:
                print("No endpoint found in log file")
                return None
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
                print()
                return suspicious_IPs
            else:
                print(5*"-","No Suspicious Activity Detected",5*"-")
                return None
    except Exception as error:
        print(error)
    print()

def save_as_csv(count_request_result, frequent_endpoint_result, suspicious_activity_result):
    with open('log_analysis_results.csv','w',newline='') as csvfile:
        writer = csv.writer(csvfile)
        if count_request_result is not None:
            writer.writerow(["Request per IP Address"])
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in count_request_result:
                writer.writerow([ip, count])
        writer.writerow([])

        if frequent_endpoint_result is not None:
            writer.writerow(["Most Frequently Acessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            endpoint, count = frequent_endpoint_result[0], frequent_endpoint_result[1]
            writer.writerow([endpoint, count])
        writer.writerow([])

        if suspicious_activity_result is not None:
            writer.writerow(["Suspicious Activity Detected"])
            writer.writerow(["IP Address", "Failded login Count"])
            for ip, count in suspicious_activity_result.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No Suspicious Activity Detected"])
        writer.writerow([])
    print("Results saved as CSV file")

log_file = input("Enter the log file name:  ")
print() 
count_request_result = Count_request(log_file)
frequent_endpoint_result = Most_frequent_endpoint(log_file)
suspicious_activity_result = Detect_suspicious_activity(log_file,5)
save_as_csv(count_request_result, frequent_endpoint_result, suspicious_activity_result)
