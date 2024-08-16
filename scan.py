import json
import time
import time
import subprocess

import maxminddb


def scan_domains(input_file):
    results = {}

    resolvers = ["208.67.222.222",
"1.1.1.1",
"8.8.8.8",
"8.26.56.26",
"9.9.9.9",
"64.6.65.6",
"91.239.100.100",
"185.228.168.168",
"77.88.8.7",
"156.154.70.1",
"198.101.242.72",
"176.103.130.130"]
    
    with open(input_file, 'r') as file:
        for domain in file:
            domain = domain.strip()
            ipv4 = []
            ipv6 = []
            timestamp = time.time()
            for resolver in resolvers:

        #IP STUFF------------------------------------------------------------
                #IPV4 ----
                try:
                    ipv4_result = subprocess.check_output(["nslookup", "-query=A", domain, resolver],
                        timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    ipv4_result = ipv4_result.split("\n")
                    for i in range(0, len(ipv4_result)):
                        if i > 1:
                            if "Address: " in ipv4_result[i]:
                                if ipv4_result[i].split(" ")[-1] not in ipv4:
                                    ipv4.append(ipv4_result[i].split(" ")[-1])

                except:
                    print(f"IP Query Failed/Timeout for {domain} using {resolver} (IPV4)")

                try:
                #IPV6 ----
                    
                    ipv6_result = subprocess.check_output(["nslookup", "-query=AAAA", domain, resolver],
                        timeout=2, stderr=subprocess.STDOUT).decode("utf-8")

                    if ("*** Can't find " + domain + ": No answer") in ipv6_result:
                        pass
                    else:
                        ipv6_result = ipv6_result.split("\n")
                        for j in range(0, len(ipv6_result)):
                            if ipv6_result[j].split(" ")[-1] not in ipv6:
                                if "Address:" in ipv6_result[j] and j > 2:
                                    ipv6.append(ipv6_result[j].split(" ")[-1])
                                    
                except:
                    print(f"IP Query Failed/Timeout for {domain} using {resolver} (IPV6)" )


        # HTTP STUFF -----------------------------------------------------------------------
                    
            redirect_to_https = False
            hsts = False
            insecure_http = False

            try:
                command = "curl -I http://" + domain + ":80"
                headers_result = subprocess.check_output(command, shell=True,
                        timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                status_code = headers_result.splitlines()[5]
                server = headers_result.split("Server: ")[1].split("\r")[0]
                insecure_http = True
            except:
                try:
                    server = headers_result.split("server: ")[1].split("\r")[0]
                except:
                    server = None
              
            if '3' in status_code: #redirect found
                redirect_count = 0
                while redirect_count < 10:
                    try:
                        newloc = headers_result.split("location: ")[1].split("\r")[0]
                    except:
                        #rint(headers_result)
                        newloc = headers_result.split("Location: ")[1].split("\r")[0]
                        
                    if "https" in newloc:
                            redirect_to_https = True
                            
                    command = "curl -I " + newloc
                    headers_result = subprocess.check_output(command, shell=True,
                        timeout=5, stderr=subprocess.STDOUT).decode("utf-8")
                    status_code = headers_result.splitlines()[5]
                    if ("HTTP/2 200" in headers_result) or '2' in status_code: #check
                        print("REDIRECT FINISHED")
                        try: 
                            if(headers_result.find('strict-transport-security')) != -1:
                                hsts = True
                        except:
                            pass #no hsts found
                        redirect_count = 11
                    elif '3' in status_code or '4' in status_code:
                        redirect_count += 1

                

                              
        #TLS --------------------------------------------------------------------------------
            tls_versions = ["tls1","tls1_1","tls1_2","tls1_3"]
            tls_results = []
            for i in tls_versions:
                try:
                    command = "echo | openssl s_client -"+ i + " -connect "+ domain +":443"
                    tls_result = subprocess.check_output(command, input=b'',
                        timeout=10, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
                    #if succeeds, no exception, TLS ver for i is found
                    if i == "tls1":
                        tls_results.append("TLSv1.0")
                    elif i == "tls1_1":
                        tls_results.append("TLSv1.1")
                    elif i == "tls1_2":
                        tls_results.append("TLSv1.2")
                    elif i == "tls1_3":
                        tls_results.append("TLSv1.3")        
                
                except:
                    print(f"TLS query failed  for {domain} with {i}")


        #CA ------------------
            try:
            
                command = "echo | openssl s_client -connect "+ domain +":443"
                CA_result = subprocess.check_output(command, input=b'',
                    timeout=10, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
                CA_result = CA_result.split("O = ")[1].split(",")[0]
            except:
                print(f"CA query failed  for {domain}")
                CA_result = None


        # RDNS names -------
            rdns_list = []
            for i in ipv4:
                try:
                    rdns_result = subprocess.check_output(["nslookup", i],
                            timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
                    res = rdns_result.split("name = ")
                    for i in range(0, len(res)):
                        if i % 2 != 0: #only odds
                            rdns_list.append(res[i].split("\n")[0][:-1])
                except:
                    print(f"RDNS query failed for {domain} IP {i}")
                

        #RTT ------------
            possible_ports = ["80", "22", "443"]
            rtt_total = []
            for i in ipv4:
                found = False
                port = 0
                while found == False and port < 3:
                    try:
                        command = 'sh -c "time echo -e \'\x1dclose\x0d\' | telnet ' + i + ' ' + possible_ports[port] + '"'
                        rtt_result = subprocess.check_output(command, input=b'', shell=True,
                                    timeout=10, stderr=subprocess.STDOUT).decode("utf-8")
                        rtt_total.append(float(rtt_result.split("\t")[1].split("\n")[0][2:-1])*100)
                        found = True
                    except:
                        print(f"RDNS query failed for {domain} IP {i} Port {possible_ports[port]}")
                        port += 1
            #parse total rtt
            rtt_range = [min(rtt_total), max(rtt_total)]
        

        # GEO ----------------
            geo_details = []
            for ip_address in ipv4:
                geo_db = maxminddb.open_database('GeoLite2-City.mmdb')
                try:
                    geo_data = geo_db.get(ip_address)

                    city_name = None
                    region_name = None
                    country_name = None

                    if "country" in geo_data and "en" in geo_data["country"]["names"]:
                        country_name = geo_data["country"]["names"]["en"]
                    elif "registered_country" in geo_data and "en" in geo_data["registered_country"]["names"]:
                        country_name = geo_data["registered_country"]["names"]["en"]
                    elif "continent" in geo_data and "en" in geo_data["continent"]["names"]:
                        country_name = geo_data["continent"]["names"]["en"]

                    if "subdivisions" in geo_data and geo_data["subdivisions"] and "en" in geo_data["subdivisions"][0]["names"]:
                        region_name = geo_data["subdivisions"][0]["names"]["en"]

                    if "city" in geo_data and "en" in geo_data["city"]["names"]:
                        city_name = geo_data["city"]["names"]["en"]

                    formatted_location = ""

                    if city_name:
                        formatted_location = city_name
                    if region_name:
                        if formatted_location:
                            formatted_location += ', '
                        formatted_location += region_name
                    if country_name:
                        if formatted_location:
                            formatted_location += ', '
                        formatted_location += country_name

                    if formatted_location not in geo_details:
                        geo_details.append(formatted_location)
                finally:
                    geo_db.close()




            results[domain] = {
                "scan_time": timestamp,
                "ipv4_addresses" : ipv4,
                "ipv6_addresses" : ipv6,
                "http_server" : server,
                "insecure_http" : insecure_http,
                "redirect_to_https" : redirect_to_https,
                "hsts": hsts,
                "tls_versions": tls_results,
                "root_ca":CA_result,
                "rdns_names": rdns_list,
                "rtt_range" : rtt_range,
                "geo_locations": geo_details

            }
            
    
    return results

def write_results(output_file, results):

    with open(output_file, "w") as f:
        json.dump(results, f, sort_keys=True, indent=4)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]")
        sys.exit(1)
    
    input_file, output_file = sys.argv[1], sys.argv[2]
    results = scan_domains(input_file)
    write_results(output_file, results)
