# whos-home
Basic home network scanner to manage what devices are on your home network(s)

### Arguments
<pre>
<b>-i --ip-range (<u>Required</u>):</b> 
    Takes IPs, CIDRS, ranges exactly the same way that nmap does.
    For example: -i "192.168.1.0/24 192.168.5.1-50" will scan all of the .1 subnet and the first 50 ips of the .5 subnet. Commas to seperate ranges/CIDRs are accepted.
<b>--ping-method</b>
    Takes either "full", "icmp" or "arp". Full combines ICMP and ARP.
<b>--port-scan</b>
    Takes either "default" or "all-ports". Default is top1k port. Both perform service scans.
<b>-A</b>
    Adds aggression to the port scan.
<b>--max-workers</b> 
    The number of port scans that will run concurrently. Default it 14.
<b>--progress-timeout</b>    
    How long until the "still scanning" prompt comes up.
</pre>
    
### Examples
```
# host discovery on .1 subnet.
python whos-home.py -i 192.168.1.0/24

# ARP host discovery on .1 subnet and first 50 IPs of .5 subnet.
python whos-home.py -i "192.168.1.0/24 192.168.5.1-50" --ping-method arp

# FULL host discovery on targets and default port scan on targets.
python whos-home.py -i "192.168.1.0/24 192.168.5.1-50" --port-scan default
```
