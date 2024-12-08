import re
import csv

# Function is use to Request Count in IP Address
def Count_request(log_file):

    try:
        with open(log_file, 'r') as file:  # open() method use to open the log file which we get in function parameter

            IP_pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'   # Pattern to search or split the IP Adress
            IP_counter = {}    #Empty Dictionary use to store the IP Adress

            for log in file: # log is iterating every line in log_file
                IP_match = re.search(IP_pattern, log)  #search() is use to find the IP Address by IP Pattern
                if IP_match:
                    # first element of the search result is IP Address, so use 0 as parameter to fetch the IP
                    IP_match = IP_match.group(0)  
                    if IP_match not in IP_counter.keys(): # Simple Condition for store IP Address in dicttionary
                        IP_counter[IP_match] = 1
                    else:
                        IP_counter[IP_match] += 1

            if IP_counter: # use to print IP Address and its count

                IP_counter = sorted(IP_counter.items(), key=lambda x:x[1], reverse=True) # Sorting by decending order
                print(5*"-","IP Address Request Count",5*"-")
                print(f"{'IP ADDRESS':<20}{'Request Count'}") # '<20' is giving free space
                #print(IP_counter)
                for IP, count in IP_counter:
                    print(f"{IP:<20}{count}")
                print()
                return IP_counter # returning the results value for save in csv file
            else:
                print("IP Address not found in given logfile")
                return None # if log file is empty
            
    except Exception as error: # Error message if any issue in logfile
        print(error)


# Function is use to find Most Frequent Endpoint
def Most_frequent_endpoint(log_file):

    try:
        with open(log_file, 'r') as file:
            endpoint_pattern = r'\"[A-Z]+\s(/[^\s]*)'  # Pattern to search or split the endpoint and Request type['GET','POST<]
            endpoint_counter = {}

            for log in file:
                endpoint_match = re.search(endpoint_pattern, log) # Search in every single line if endpoint is defined
                if endpoint_match:
                    endpoint_match = endpoint_match.group(1) # we get request type and endpoint name by search pattern
                    #seperate Endpoint name alone by 1 in group
                    if endpoint_match not in endpoint_counter: # Storing technique
                        endpoint_counter[endpoint_match] = 1
                    else:
                        endpoint_counter[endpoint_match] += 1

            if endpoint_counter: # if get endpoint

                endpoint_counter = sorted(endpoint_counter.items(), key=lambda x:x[1], reverse=True) # Sorted in decending order
                frequent_endpoint = endpoint_counter[0] # endpoint_counter hold the endpoint and its count, top most is highest count
                # so get the first element of endpoint_counter
                print(4*'-',"Most Frequently Accessed Endpoint",4*'-')
                print(f'\t{frequent_endpoint[0]} (Accessed {frequent_endpoint[1]} Times)')
                print()
                return frequent_endpoint #return the result for save in csv file
            
            else:
                print("No endpoint found in log file")
                return None # if log file is emplty
            
    except Exception as error:  # any issue in lof_file
        print(error)


# Function is use to Detect Suspicious Activity
def Detect_suspicious_activity(log_file, thershold = 10): # pass the thershold as 10 to define the thershold is 10 in defaults

    IP_pattern = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' # Pattern for search the IP Address in log_file
    failed_logins = {}
    # Pattern for search 'Invalid credentials' log_file line to identify the log as failed login
    failed_logins_pattern = r' 401 |Invalid credentials' 

    try:
        with open(log_file, 'r') as file:
            for log in file:
                if re.search(failed_logins_pattern, log): # check the line is hold the 'Invalid credentials' message
                    IP_match = re.search(IP_pattern, log) # seperate the IP in line by IP pattern
                    if IP_match:
                        IP_match = IP_match.group(0)
                        if IP_match not in failed_logins.keys(): # Storing technique
                            failed_logins[IP_match] = 1
                        else:
                            failed_logins[IP_match] += 1
            # Filetr the IPs by thershold in no of times failed login count
            suspicious_IPs = {IP:count for IP, count in failed_logins.items() if count >= thershold}

            if suspicious_IPs: # if IPs failed login count has greater than or eqaul to thershold
                print(5*"-","Suspicious Activity Detected",5*"-")
                print(f"{'IP ADDRESS':<20}{'Failed Login Atempts'}")
                for ip, count in suspicious_IPs.items():
                    print(f"{ip:<20}{count}")
                print()
                return suspicious_IPs # return the result to save in csv file
            else:
                print(5*"-","No Suspicious Activity Detected",5*"-")
                return None # IF no IPs meet the thershold counts
            
    except Exception as error: # if any issue in log_file
        print(error)
    print()

def save_as_csv(count_request_result, frequent_endpoint_result, suspicious_activity_result):

    with open('log_analysis_results.csv','w',newline='') as csvfile: # opening the csv file in writer mode 'w'
        writer = csv.writer(csvfile) # make the writer variable 

        if count_request_result is not None: # if get the results then gone to save in csv file
            writer.writerow(["Request per IP Address"]) # writerow() is use to write one row at last of the file 
            writer.writerow(["IP Address", "Request Count"]) 
            for ip, count in count_request_result:
                writer.writerow([ip, count]) # writing the result data
        writer.writerow([]) # empty row

        if frequent_endpoint_result is not None: # if get the results then gone to save in csv file
            writer.writerow(["Most Frequently Acessed Endpoint"]) # writerow() is use to write one row at last of the file
            writer.writerow(["Endpoint", "Access Count"])
            endpoint, count = frequent_endpoint_result[0], frequent_endpoint_result[1]
            writer.writerow([endpoint, count]) # writing the result data
        writer.writerow([])

        if suspicious_activity_result is not None: # if any detected in results then gone to save in csv file
            writer.writerow(["Suspicious Activity Detected"]) # writerow() is use to write one row at last of the file
            writer.writerow(["IP Address", "Failded login Count"])
            for ip, count in suspicious_activity_result.items():
                writer.writerow([ip, count]) # writing the result data
        else:
            writer.writerow(["No Suspicious Activity Detected"]) # if we not found any detection we just write like not detected
        writer.writerow([])

    print("Results saved as CSV file")

log_file = input("Enter the log file name:  ") # geting file name
print() 

#calling functions
count_request_result = Count_request(log_file)
frequent_endpoint_result = Most_frequent_endpoint(log_file)
suspicious_activity_result = Detect_suspicious_activity(log_file,5) # Passed the thershold as 5
save_as_csv(count_request_result, frequent_endpoint_result, suspicious_activity_result)
