#!/bin/bash
BASE=$(cat /etc/qlx/BASE)

searches=(
	    "There is no app configured at that hostname"
	    "NoSuchBucket"
	    "No Such Account"
	    "You're Almost There"
	    "a GitHub Pages site here"
	    "this shop is currently unavailable"
	    "There's nothing here"
	    "The site you were looking for couldn't be found"
	    "project not found"
	    "Your CNAME settings"
	    "The resource that you are attempting to access does not exist or you don't have the necessary permissions to view it."
	    "Domain mapping upgrade for this domain not found"
	    "The feed has not been found"
	    "This UserVoice subdomain is currently available!"
	    "The specified bucket does not exist"
	    "Repository not found"
	    "Fastly error: unknown domain:"
	    "The feed has not been found."
	    "The thing you were looking for is no longer here, or never was"
	    "404 Blog is not found"
	    "We could not find what you're looking for"
	    "No settings were found for this company"
	    "Uh oh. That page doesn't exist"
	    "is not a registered InCloud YouTrack"
	    "No Site For Domain"
	    "It looks like you may have taken a wrong turn somewhere"
	    "Project doesnt exist"
	    "Unrecognized domain"
	    "Whatever you were looking for doesn't currently exist at this address"
	    "Do you want to register"
	    )

rocon(){
	local url=$1
	local blog="${BASE}/${url}/".buckets.log
	local slog="${BASE}/${url}/".sdomain.log
	local out="${BASE}/${url}/"out

	rm -f ${blog}
	grep --color -Pri \
		'(/|2F)?\K([\w\.\-_]+)\.(amazonaws\.com|digitaloceanspaces\.com|blob\.core\.windows\.net)(/|%2F)?([\w\.\-_]+)?' "${BASE}/${url}"/out/* >> ${blog}

	rm -f ${slog}

	for str in "${searches[@]}"; do
		grep --color -Hnri "$str" "${BASE}/${url}"/out/* >> ${slog}
	done
}

if [[ "$1" == "all" ]];then
	for i in $(ls ${BASE});do
		num=$(ls "${BASE}/${i}" |wc -l)
		if [ "$num" -gt 6 ];then
			echo "[+]roconing "${i}
			rocon ${i}
		fi
	done
else
	rocon "${1}"
fi