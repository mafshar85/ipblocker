log_path=$1
n=$2

# TODO: Block IPs with more than n request per minute by iptables

awk -F" " '{if(ar[$1])ar[$1]=ar[$1]""$4  ; else ar[$1]=$4 ;}END {for (i in ar)print i ,ar[i] }' OFS=" "  $1>px

sudo python3 p.py $2 $1
