import openpyxl
import re
import ipaddress
import yaml
import sys
#Script for risk assessment for Palo Alto firewall rules.
#Programmer Juan Davila.

controlfile = sys.argv[1]
template = ''
cdes = []
firewall_name = ''
sbu = ''
output = ''
cde_ips = []
cde_groups = [] #List of CDES in palo alto format, and also list will be populated with object groups related to CDE IPs and CDE IPs.

with open(controlfile) as file:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
    control_file_items = yaml.load(file, Loader=yaml.FullLoader)
    firewall_name = control_file_items['firewall_name']
    template = control_file_items['template_to_analyze']
    cdes = control_file_items['cde_subnets']
    sbu = control_file_items['sbu']
    output = control_file_items['output']
    
unsecure_ports = ['rsh', '-514$', '-514;', 'telnet', '-23$', '-23;',
                  'ftp', '-21$', '-21;', 'http$', 'http;', 'www', '-80$',
                  '-80;', '-137$', '-137;', '-138$', '-138;', '-139$', '-139;',
                  '-5900$', '-5900;' 'netbios-ns', 'netbios-dgm', 'netbios-ssn',
                  'tftp', '1024-65535'
                  ]

#Unsecure_ports + object groups related to unsecure ports.
unsecure_ports_all = ['rsh', '-514$', '-514;', 'telnet', '-23$',
                      '-23;', 'ftp', '-21$', '-21;', 'http$', 'http;',
                      'www', '-80$', '-80;', '-137$', '-137;', '-138$',
                      '-138;' '-139$', '-139;', '-5900$', '-5900;', 'netbios-ns',
                      'netbios-dgm', 'netbios-ssn', 'tftp', '1024-65535'
                      ]
#Networks considered as any.
anynet = ['any', 'N-10.0.0.0-8', '10.0.0.0-8']

#ICMP protocol words.
icmp = ['icmp', 'ping', 'trace-route', 'traceroute', 'ospf']

#Full IP access words.
full_ip = ['any', 'all-tcp', 'all-udp', 'tcp-all', 'udp-all']

big_nets = ["\d-{}$".format(num) for num in range(8,23) or "\d-{};".format(num2) for num2 in range(8,23)] ## REGEX format to look for big networks mask -8 to -23 match within object_groups.

big_nets_and_objects = ["\d-{}$".format(num) for num in range(8,23) or  "\d-{};".format(num2) for num2 in range(8,23)]# REGEX format to look for big networks mask -8 to -23  + bignets object group names


PAReview = openpyxl.load_workbook(template) ## File to Analyze variable.
dump = PAReview['FW Dumps-Review'] #Policies TAB Variable.
object_groups = PAReview['Object-group'] #Network Object groups tab variable.
service_ports = PAReview['Service-object'] #Ports object groups tab variable.

###########STEP 1 CREATE A LIST OF ALL POSSIBLE IPS WITHIN CDEs##############
for ip_string in cdes:
    ip_string_pa = ip_string.replace("/", "-")
    cde_groups.append(ip_string_pa)
    
for cde in cdes:
    for ip in ipaddress.IPv4Network(cde):#Creates list of IPs inside network using ipaddress module.
        cde_groups.append(str(ip)) #Append IP in normal format x.x.x.x to cde_groups.
        cde_groups.append('H-'+str(ip)+'-32')#Appends HOSTS IP in Palo Alto format H-x.x.x.x-32 to cde_groups.
#print(cde_groups)
#############

###STEP 2 Filter objects associated with unsecure ports#######

def unsecure_ports_analyze(x): ## x is equal to the service_ports tab.
    row_object_groups = 2
    for line in x:
        addresses = x['D' + str(row_object_groups)]
        name = x['A' + str(row_object_groups)]
        if addresses.value == None:
            break
        for port in unsecure_ports:
            match = re.search(port, addresses.value)
            if match:
                n = name.value
                if n not in unsecure_ports_all:
                    unsecure_ports_all.append(name.value)
        row_object_groups += 1

        
####STEP 3 Filter objects big nets #####

def big_nets_filter(x): ### is equal to object_groups tab.
    row_big_nets = 2
    for line in x:
        addresses = x['D' + str(row_big_nets)]
        name = x['A' + str(row_big_nets)]
        all_addresses = []
        if addresses.value == None:
            break
        if 'N-' in addresses.value:
            for n in big_nets:
                match = re.search(n, addresses.value)
                if match:
                    object_name = name.value
                    if object_name not in big_nets_and_objects:
                        big_nets_and_objects.append(name.value)
        row_big_nets += 1
    

### STEP 4 Obtain object groups associated with CDEs#####
def cde2obj(x): ###Obtain Object Groups associated with CDEs###
    row_cde_obj = 2
    for line in x:
        addresses = x['D' + str(row_cde_obj)]
        name = x['A' + str(row_cde_obj)]
        if addresses.value == None:
            break
        for cde in cde_groups:
            if str(cde) in str(addresses.value) and str(name.value) not in cde_groups: #ADDED str().
                cde_groups.append(name.value)
        row_cde_obj += 1
    #print(cde_groups)
#####Sep 4 END###

#####Sep 5 START###
def any_net(x): ###Obtain Object Groups associated with ANY or 10.0.0.0/8###
    row_cde_obj = 2
    for line in x:
        addresses = x['D' + str(row_cde_obj)]
        name = x['A' + str(row_cde_obj)]
        if addresses.value == None:
            break
        for net in anynet:
            if net in addresses.value and name.value not in anynet:
                anynet.append(name.value)
        row_cde_obj += 1
    #print(cde_groups)

#####Sep 5 END###

### STEP 6 Analyze File rule by rule ###

                
def analyze(d): #d equals variable of FW Dumps-review tab, defined above.
    #print(cde_groups)
    row_dump = 7 #First line with rule in PA REVIEW.
    for line in d: #For every line in the file.
        lineno = d['A' + str(row_dump)] #number of line.
        if lineno.value == None: ## Test november 2021.
            break
        source_address = d['G' + str(row_dump)]
        dest_address = d['I' + str(row_dump)]
        application = d['J' + str(row_dump)]
        service = d['K' + str(row_dump)]
        action = d['L' + str(row_dump)]
        all_source_addresses = [] #List of all source addresses gotten from source_address.value.
        all_dest_addresses = [] #List of all dest addresses gotten from dest_address.value.
        source_cde_flag = 'N' #Flag to identify if Source Address contains CDE IP, default N.
        dest_cde_flag = 'N' #Flag to identify if Dest Address contains CDE IP, default N.
        assessed = ''
        default_risk = 'PASS' #Default risk assessment pass, will be overwritten if other conditions are meet, described below.
        d['M' + str(row_dump)].value = default_risk #Applying default risk for rules.

        if source_address.value == None:
            break
        if dest_address.value == None:
            break
        if 'allow' in action.value.lower(): #Analyze only rules marked as allowed.##Update add .lower() on november 2th 2021.
            if ';' in str(source_address.value): #When ; is in source_address.value it means there are several IPs in source_address. 02082022 added str()
                sources_splitted = source_address.value.split(';') #We split source_addresses ; separated.
                for sc in sources_splitted:#For every IP in source address after been splitted.
                    if sc not in all_source_addresses:#IF it's not existent in all_source_addresses, append it.
                        all_source_addresses.append(sc)
            if ';' not in str(source_address.value):#Source only has one IP. 02092022 ADDED str()
                all_source_addresses.append(source_address.value)#Append to all_source_addresses.
            if ';' in str(dest_address.value): #ADDED str()
                dest_splitted = dest_address.value.split(';')
                for dc in dest_splitted:
                    if dc not in all_dest_addresses:
                        all_dest_addresses.append(dc)
            if ';' not in str(dest_address.value): #ADDED str()
                all_dest_addresses.append(dest_address.value)

            for i in cde_groups:
                if str(i) in str(source_address.value): #ADDED str()
                    source_cde_flag = 'Y'
                    for address in all_dest_addresses:
                        for n in big_nets_and_objects:
                            match = re.search(n, address)
                            if match:
                                ###MARK AS MEDIUM
                                med1 = 'MEDIUM'
                                d['M' + str(row_dump)].value = med1
                                r1 = 'Scope'
                                d['N' + str(row_dump)].value = r1
                    for port in full_ip:
                        port_match = re.search(port, service.value.lower())
                        if port_match:
                            ###MARK AS HIGH
                            med1 = 'HIGH'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'Full IP'
                            d['N' + str(row_dump)].value = r1
                    for net in anynet:
                        if net in dest_address.value:
                            ###MARK AS HIGH
                            med1 = 'HIGH'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'Any source/destination'
                            d['N' + str(row_dump)].value = r1
                            for port in full_ip:
                                port_match = re.search(port, service.value)
                                if port_match:
                                    ###MARK AS VERY HIGH
                                    med1 = 'VERY HIGH'
                                    d['M' + str(row_dump)].value = med1
                                    r1 = 'IP any any'
                                    d['N' + str(row_dump)].value = r1
                    for port in unsecure_ports_all:
                        port_match = re.search(port, service.value)
                        if port_match:
                            ###MARK AS MEDIUM
                            med1 = 'MEDIUM'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'Unsecure'
                            d['N' + str(row_dump)].value = r1
                    if 'any' in application.value and 'any' in service.value:
                        ###MARK AS HIGH
                        med1 = 'HIGH'
                        d['M' + str(row_dump)].value = med1
                        r1 = 'Full IP'
                        d['N' + str(row_dump)].value = r1 
                            
                if str(i) in str(dest_address.value):
                    for address in all_source_addresses:
                        for n in big_nets_and_objects:
                            match = re.search(n, address)
                            if match:
                                ###MARK AS MEDIUM
                                med1 = 'MEDIUM'
                                d['M' + str(row_dump)].value = med1
                                r1 = 'Scope'
                                d['N' + str(row_dump)].value = r1
                    for port in full_ip:
                        port_match = re.search(port, service.value.lower())
                        if port_match:
                            ###MARK AS HIGH
                            med1 = 'HIGH'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'Full IP'
                            d['N' + str(row_dump)].value = r1
                    for net in anynet:
                        if net in source_address.value:
                            ###MARK AS HIGH
                            med1 = 'HIGH'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'Any source/destination'
                            d['N' + str(row_dump)].value = r1
                            for port in full_ip:
                                port_match = re.search(port, service.value.lower())
                                if port_match:
                                    ###MARK AS VERY HIGH
                                    med1 = 'VERY HIGH'
                                    d['M' + str(row_dump)].value = med1
                                    r1 = 'IP any any'
                                    d['N' + str(row_dump)].value = r1
                    for port in unsecure_ports_all:
                        port_match = re.search(port, service.value)
                        if port_match:
                            ###MARK AS MEDIUM
                            med1 = 'MEDIUM'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'Unsecure'
                            d['N' + str(row_dump)].value = r1
                    if 'any' in application.value and 'any' in service.value:
                        ###MARK AS HIGH
                        med1 = 'HIGH'
                        d['M' + str(row_dump)].value = med1
                        r1 = 'Full IP'
                        d['N' + str(row_dump)].value = r1

            for i2 in cde_groups:
                #print(i2)
                if str(i2) in str(dest_address.value): #ADDED str() for better detection.
                    dest_cde_flag = 'Y'

            if source_cde_flag == 'N' and dest_cde_flag == 'N':
                    ###MARK AS NOT ASSESSED
                    med1 = 'NOT ASSESSED'
                    d['M' + str(row_dump)].value = med1
                    r1 = 'Does not contain cde subnets'
                    d['N' + str(row_dump)].value = r1
            for net in anynet:
                if str(net) in str(source_address.value):
                    ###MARK AS HIGH
                    med1 = 'HIGH'
                    d['M' + str(row_dump)].value = med1
                    r1 = 'Any source/destination'
                    d['N' + str(row_dump)].value = r1
                    for protocol in full_ip:
                        if protocol in str(service.value).lower():
                            ###MARK AS HIGH
                            med1 = 'VERY HIGH'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'IP any any'
                            d['N' + str(row_dump)].value = r1
                if str(net) in str(dest_address.value): #ADDED str()
                    ###MARK AS HIGH
                    med1 = 'HIGH'
                    d['M' + str(row_dump)].value = med1
                    r1 = 'Any source/destination'
                    d['N' + str(row_dump)].value = r1
                    for protocol in full_ip:
                        if protocol in service.value.lower():
                            ###MARK AS HIGH
                            med1 = 'VERY HIGH'
                            d['M' + str(row_dump)].value = med1
                            r1 = 'IP any any'
                            d['N' + str(row_dump)].value = r1
            if 'any' in str(source_address.value) and 'any' in str(dest_address.value):
                if 'any' in str(application.value) and 'any' in str(service.value):
                    ###MARK AS VERY HIGH
                    med1 = 'VERY HIGH'
                    d['M' + str(row_dump)].value = med1
                    r1 = 'IP any any'
                    d['N' + str(row_dump)].value = r1
                
            for ic in icmp:
                if ic in application.value.lower():
                    ###MARK AS MEDIUM
                    med1 = 'LOW'
                    d['M' + str(row_dump)].value = med1
                    r1 = 'Icmp, Scope'
                    d['N' + str(row_dump)].value = r1
        if 'deny' in action.value:
            ###MARK AS PASS
            med1 = 'PASS'
            d['M' + str(row_dump)].value = med1



        row_dump += 1
                        
    d['C1'].value = sbu
    d['C2'].value = firewall_name
    PAReview.save(output) 
                        
print("####################### STARTING #######################")
print("####################### PALO ALTO FIREWALL REVIEW V1 #######################")
print("\n")
print("####################### USING CONTROL FILE: {} #######################".format(controlfile))
print("####################### FIREWALL TO ANALYZE: {} #######################".format(firewall_name))
print("####################### BUSINESS UNIT: {} #######################".format(sbu))
print("####################### CDEs NETWORKS IN SCOPE FOR REVIEW: {} #######################".format(cdes))
print("####################### FILE TO REVIEW: {} #######################".format(template))
print("\n")

#STEP 2
print("########### ADDING SERVICE-GROUPS WITH UNSECURE PROTOCOLS FROM TEMPLATE TO UNSECURE PROTOCOLS LIST #########")
unsecure_ports_analyze(service_ports) ##Create a list of unsecure ports and object-groups associated with unsecure ports.
#STEP 3
print("################ ADDING BIG NETWORKS OBJECT GROUPS FROM TEMPLATE TO BIG NETWORKS LIST#######################")
big_nets_filter(object_groups) ##Create a list of big networks regex and object-groups associated with big networks.
#STEP 4
print("################ ADDING OBJECT GROUPS ASSOCIATED WITH CDE IPs FROM TEMPLATE TO CDE IP LIST #######################")
cde2obj(object_groups)### Create a list of the cde IPs and object groups associated with IPs.
#STEP 5
print("####################### CREATING **ANY** NETWORK GROUPS LIST #######################")
any_net(object_groups)### Create a list of object groups associated with any or 10.0.0.0/8
#print(anynet)
#STEP 6
print("####################### ANALYZING RULES FROM TEMPLATE #######################")
analyze(dump) ## Analyze Palo Alto dumps, dump = FW Dumps-review tab, dump defined above.

print("####################### REVIEW HAS BEEN COMPLETED SUCCESFULLY SAVED AS {} #######################".format(output))
print("####################### END #######################")
