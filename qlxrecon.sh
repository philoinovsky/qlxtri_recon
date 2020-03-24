#!/bin/bash
BASE=$(cat /etc/qlx/BASE)
lists='/usr/share/wordlists'
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
cyan=`tput setaf 6`
reset=`tput sgr0`
service mysql start
echo -e """
${cyan}
   ____ _      _        _       __                      
  /___ \ |_  _| |_ _ __(_)     /__\ ___  ___ ___  _ __  
 //  / / \ \/ / __| '__| |    / \/// _ \/ __/ _ \| '_ \ 
/ \_/ /| |>  <| |_| |  | |   / _  \  __/ (_| (_) | | | |
\___,_\|_/_/\_\\__|_|  |_|___\/ \_/\___|\___\___/|_| |_|
                        |_____|                                                       
Qlxtri_Recon ${reset}By ${red}Qlxtri${reset}
"""

show_help () {
	echo """
usage: 
	$0 -u <host.com>
	-u, --url, the target url

(optional):
	-t --time delay, defines meg delay, delay time to the same host, default 200
	-r --reset, remove all, hosts, domains, out, out_config, out_opre, out_crlf, out_pxss, database
	-d --debug, debug mode, standard error will be shown on screen
	-D --delete, delete only, parameters same as reset

example:
	$0 -u example.com -t 300 -r hosts,out_config -d
"""
	exit
}

parse_pm () {	
	threads=200
	while [ "$1" != "" ]; do
		case $1 in
			-u | --url )		shift
								host_name=$1
								echo "${green}[+]${reset}working on ${host_name}"
						;;
			-t | --time )		shift
								if [[ $(is_num "$1") -eq 0 ]]; then echo "${yellow}[!]${reset}threads must be an integer"; exit; else threads=$1;fi
								;;
			-r | --reset )		shift
								reset_list=$1
								;;
			-h | --help )       show_help
								exit
								;;
			-d | --debug )		debug_tag=1
								;;
			-D | --delete )		shift
								reset_list=$1
								exit_tag=1
								;;
			* )					echo "${yellow}[!]${reset}unknown parameter '$1'"
								show_help
								exit 1
		esac
		shift
	done
	if [[ $debug_tag -ne 1 ]];then exec 2>/dev/null ;fi
	if [ -z $host_name ]; then 
		show_help
	else 
		mkdir -p $BASE"/${host_name}"
		table_name=$(echo $host_name | replace "." "_")
	fi
	if ! [ -z $reset_list ];then reset ;fi
	if [[ "$exit_tag" -eq 1 ]];then exit ;fi
}

is_num() {
	local number=$1
	local regex='^[0-9]+$'
	if ! [[ $number =~ $regex ]] ; then
   		echo "0"
	else
		echo "1"
	fi
}

check_table (){
	table=$(mysql -u root -e "use recon;show tables"| grep "$table_name")
	if [ "$table_name" != "$table" ];then
		echo "${red}[*]${reset}table doesn't exist"
		mysql_create_table $table_name
	fi
	echo "${green}[+]${reset}table created "$table
	declare -A arr_ip
}

reset () ( #outerfunction and innerfunction
	domains() { rm -f $BASE"/${host_name}/"domains;}
	hosts() { rm -f $BASE"/${host_name}/"hosts; }
	out() { rm -rf $BASE"/${host_name}/out"; }
	out_config() { rm -rf $BASE"/${host_name}/out_config"; }
	out_opre() { rm -rf $BASE"/${host_name}/out_opre"; }
	out_crlf() { rm -rf $BASE"/${host_name}/out_crlf"; }
	out_pxss() { rm -rf $BASE"/${host_name}/out_pxss"; }
	database() { mysql -u root -e "USE recon; DROP TABLE ${table_name}"; }
	del_cors() { rm -f $BASE"/${host_name}/cors"; }
	local reset_paras=$(echo "$reset_list" | sed 's/,/ /g' )
	echo "${red}[*]${reset}resetting ${reset_paras}"
	for reset_para in "${reset_paras[@]}";do
		case $reset_para in
			all )			domains;hosts;out;out_config
						out_opre;out_crlf;out_pxss;database
						;;
			domains )		domains
						;;
			hosts )			hosts
						;;
			out )			out
						;;
			out_config )		out_config
						;;
			out_opre )		out_opre
						;;
			out_crlf )		out_crlf
						;;
			out_pxss )		out_pxss
						;;
			cors )			del_cors
						;;	
			database )		database
						;;
			* )			echo "${yellow}[!]${reset}reset parameter out of range"
						exit 1
		esac
	done
	echo "${green}[+]${reset}${reset_paras} was reset"
)

check_exec (){
	# $1 = file to be checked; $2 = function name
	local file_name=$1
	local func_name=$2
	if ! [ -s "${BASE}/${host_name}/${file_name}" ];then
		echo "${red}[*]${reset}${func_name} is working"
		exec_func "${func_name}"
	fi
	local file_date=$(date -r "${BASE}/${host_name}/${file_name}" "+%Y-%m-%d %H:%M:%S")
	echo "${green}[+]${reset}${func_name} was done at ${file_date}"
}

exec_func (){
	local func_name=$1
	case $func_name in
		assetfinder )	
			rm -f $BASE"/${host_name}/"domains
			amass enum --passive -d $host_name | awk -F"/" '{n=split($1, a, ".");printf("%s.%s.%s\n", a[n-2],a[n-1], a[n])}' | sort -u > $BASE"/"$host_name"/".secondroot
			for url_ass in $(cat ${BASE}"/"${host_name}"/".secondroot);do
				assetfinder --subs-only $url_ass | sort -u >> $BASE"/${host_name}/"domains
			done;	
		#	assetfinder --subs-only $host_name | sort -u > $BASE"/${host_name}/"domains
			;;
		httprobe )		
			cat $BASE"/${host_name}/"domains | httprobe | sort -u > $BASE"/${host_name}/"hosts
			;;
		host )			
			mkdir $BASE"/${host_name}/out/" 
			meg -d $threads / "$BASE/${host_name}/hosts" $BASE"/${host_name}/out"
			;;
		config )
			meg -d $threads "${lists}/configfiles" "${BASE}/${host_name}/hosts" $BASE"/${host_name}/out_config"
			;;
		opre )
			meg -d $threads -r "${lists}/openredirects" "${BASE}/${host_name}/hosts" $BASE"/${host_name}/out_opre"
			;;
		crlf )
			meg -d $threads -r "${lists}/crlfinjection" "${BASE}/${host_name}/hosts" $BASE"/${host_name}/out_crlf"
			;;
		pxss )
			meg -d $threads /bounty%3c%22pls "${BASE}/${host_name}/hosts" $BASE"/${host_name}/out_pxss"
			;;
		cors )
			cors "${BASE}/${host_name}/hosts"
			;;
	esac
}

mysql_create_table (){
	table_name=$1
	mysql -u root -e \
		"USE recon;
		CREATE TABLE IF NOT EXISTS ${table_name} (
		id INT AUTO_INCREMENT ,
		host VARCHAR(100) NOT NULL ,
		path VARCHAR(100) ,
		ip VARCHAR(17) ,
		status INT ,
		type VARCHAR(20) ,
		server VARCHAR(100) ,
		location VARCHAR(30),
		title VARCHAR(100) ,
		content VARCHAR(255) ,
		PRIMARY KEY (id)) ;"
}

mysql_insert() (
	host_process(){
		return_tag=0	
	}
	config_process(){
		if [ "$status" -ne 200 -o "$u_path" = "/" ] ;then
			rm -f "$f_path"
			return_tag=1
		else
			content=$host$u_path
			return_tag=0
		fi
	}
	opre_process(){
		loc=$(grep -HnriE '< location: (https?:)?[/\\]{2,}example.com' "$f_path")
		if [ -z $loc ];then
			rm -f "$f_path"
			return_tag=1
		else
			location=$loc
			return_tag=0
		fi
	}
	crlf_process(){
		con=$(grep -HnriE "< Set-Cookie: ?crlf" "$f_path")
		if [ -z $con ];then
			rm -f "$f_path"
			return_tag=1
		else
			content=$con
			return_tag=0
		fi 
	}
	pxss_process(){
		con=$(grep -Hrie '(bounty<|"pls)' "$f_path")
		if [ -z $con ];then
			rm -f "$f_path"
			return_tag=1
		else
			content=$con
			return_tag=0
		fi 
	}
	cors_process(){
		local host=$(echo -n "$line" | cut -d " " -f 1)
		local key=$(echo -n "$host" | awk -F \/ '{print $3}' | replace "." "_")
		local content="$line"
		mysql -u root -e \
			"INSERT INTO recon.${table_name}
				 (host,path,ip,status,type,server,location,title,content)
			VALUES ('${host}','','${arr_ip["${key}"]}','',
				'cors','','','','${content}')"
	}
	local line="${1}"
	local type="${2}"
	return_tag=0
	case $type in
		cors )			cors_process
					;;
	esac
	if [ "$return_tag" -eq 1 ];then return;fi
	local f_path=$(echo -n "$line" | cut -d " " -f 1)
	local u_path="/"$(echo -n "$line" | cut -d " " -f 2 | cut -d "/" -f 4-)
	local host=$(echo -n "$line" | cut -d " " -f 2 | awk -F \/ '{print $1"//"$3}')
	echo -ne "\e[0K\r${red}[*]${reset}processing $host"
	local status=$(echo -n "$line" | cut -d " " -f 3 | cut -d "(" -f 2)
	let local status_100=$status/100
	case $type in
		host )			host_process
					;;
		config ) 		config_process
					;;
		opre )			opre_process
					;;
		crlf )			crlf_process
					;;
		pxss )			pxss_process
					;;
	esac
	if [ "$return_tag" -eq 1 ];then return;fi
	if [ "$status_100" -eq 3 ];then
		local location="$location"$(cat "$f_path" | grep "[Ll]ocation: "| awk -F": " '{print $2}')
	fi
	local domain=$(echo -n "$line" | cut -d " " -f 2|awk -F \/ '{print $3}')
	local key=$(echo -n "$domain" | replace "." "_")
	if [ $arr_ip["${key}"] = "[${key}]" ];then
		local ip=$(echo $(host "$domain" | awk '/has address/ { print $4 }') | awk -F ' ' '{print $1}')
		arr_ip["${key}"]=$ip
	fi
	local content="$content"$(echo $(html h1 "${f_path}") $(html h2 "${f_path}") $(html h3 "${f_path}") $(html h4 "${f_path}") $(html p "${f_path}") | replace "'" "\'" | tr "\n" " ")
	local title=$(html title "${f_path}" | replace "'" "\'" | tr "\n" ",")
	local server=$(cat "$f_path" | grep "[Ss]erver: "| awk -F": " '{print $2}')
	#$f_path $host $status $title $alive $host_name domain ip
	mysql -u root -e \
		"INSERT INTO recon.${table_name}
			 (host,path,ip,status,type,server,location,title,content)
		VALUES ('${host}','${u_path}','${arr_ip["${key}"]}','${status}',
			'${type}','${server}','${location}','${title}','${content}')"
)

mysql_update_table (){
	local type=$1
	echo "${red}[*]${reset}parsing file and updating database"
	echo -n "${red}[*]${reset}waiting"
	while IFS= read -r line
	do
		mysql_insert "${line}" "$type"
	done < "$input"
	echo -e "\e[0K\r${green}[+]${reset}database updated                                       "
}

mysql_check_exec (){
	local type=$1
	local func=$2
	local check=$(mysql -u root -e "use recon;select type from ${table_name} where type = '${type}' LIMIT 1"| grep "${type}")
	if [ -z $check ];then
		mysql_update_table $type
	fi
	echo "${green}[+]${reset}${type} in database now"
}


html(){
	local tag=$1
	local f_path=$2
	echo $f_path | html-tool tags $tag
}

cors()(
	local urlsfile=$1
	CORS=()
	CREDS=()

	checkacao() {
	    local url=$1
	    local origin=$2
	    curl -vs --max-time 9 "$url" -H"Origin: $origin" 2>&1 | grep -i "< Access-Control-Allow-Origin: $origin" &> /dev/null
	}

	checkacac() {
	    local url=$1
	    local origin=$2
	    curl -vs --max-time 9 "$url" -H"Origin: $origin" 2>&1 | grep -i "< Access-Control-Allow-Credentials: true" &> /dev/null
	}

	while read -r url; do
	    local domain=$(echo "$url" | sed -E 's#https?://([^/]*)/?.*#\1#')
	    for origin in https://evil.com null https://$domain.evil.com https://${domain}evil.com https://${domain}'!.evil.com'; do
		if checkacao "$url" "$origin"; then
		    CORS+=("$url might be vulnerable with origin '$origin'")$'\n'
		    if checkacac "$url" "$origin"; then           
		        CREDS+=("$url with origin '$origin' has Allow-Credentials: true")$'\n'
		    fi
		fi
		sleep 2
	    done
	done < $urlsfile
	echo "cors" > "${BASE}/${host_name}/cors"
	if [[ ${#CORS[@]} -gt 0 ]]; then
		echo "${CORS[@]}" >> "${BASE}/${host_name}/cors"
	fi

	if [[ ${#CREDS[@]} -gt 0 ]]; then
		echo "${CREDS[@]}" >> "${BASE}/${host_name}/cors"
	fi
)

check_both_exec(){ #exec_name same as type
	local file_name=$1
	local mysql_type=$2
	local exec_name=$2
	check_exec ${file_name} ${exec_name}
	input="${BASE}/${host_name}/${file_name}"
	mysql_check_exec ${mysql_type}
}

#main part of programme starts here
#parsing parameters host_name threads reset
parse_pm $*
check_table

check_exec domains assetfinder
check_exec hosts httprobe

hosts_num=$(cat ${BASE}/${host_name}/hosts|wc -l)
if [ "$hosts_num" -gt 5000 ];then
	echo "${host_name} hosts too many, abort" | tee ${BASE}/${host_name}/.error.log
	exit 
fi

#meg, meg_config, meg_opre, meg_crlf, meg_pxss, cors
#check_both_exec out_config/index config
check_both_exec out/index host
check_both_exec out_opre/index opre
check_both_exec out_crlf/index crlf
check_both_exec out_pxss/index pxss
check_both_exec cors cors

#done
echo "${green}[+]${reset}recon session done"