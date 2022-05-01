#!/bin/bash
    
     
     
    # Check if the file exists (in the current directory) and if yes, remove it
    if [ -f "$1-aggregated.zone" ]
    then
    	rm $1-aggregated.zone
    fi
     
    # Download the aggregate zone file for the requested country
    wget https://www.ipdeny.com/ipblocks/data/aggregated/$1-aggregated.zone
     
     
    # Check if there was an error
    if [ $? -eq 0 ]
    then
    	echo "Download Finished!"
    else
        echo "Download Failed!" >&2
        exit 1
     
    fi
     
    # Creating a new set of type hash:net (nethash)
    ipset -N $2 hash:net -exist
     
    # Flushing the set
    ipset -F $2
     
     
     
    # Iterate over the file and add them to the set
    echo "Adding Networks to set..."
    for i in `cat $1-aggregated.zone`
    do
    	ipset -A $2 $i
    done
     
     
     
    # Adding a rule that references to the set and drops based on source IP address
    echo -n "Blocking $2 with iptables ... "
    iptables -I INPUT -m set --match-set $2 src -j DROP
    echo "Done"