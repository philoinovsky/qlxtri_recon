#!/bin/bash
BASE='/root/workspace'
URL=$1
PATH="${BASE}/${URL}"
red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

inc="$(tr '\n' '|'<${PATH}/scope)";
inc="${inc}Qlxtri"

exc="$(tr '\n' '|'<${PATH}/../conf/exclude)";
exc="${exc}Qlxtri"

# start
rm links;

# scripts cleansing
echo "${green}[*]${reset}sorting $(wc -l scripts)";
sort -u scripts > tmp;
egrep $inc tmp > scripts;

# generate links using linkfinder
echo "${green}[*]${reset}utilizing linkfinder.py against sorted $(wc -l scripts)"
for i in $(cat scripts); do 
	echo "${green}[*]${reset}now ${red}PanYue ${reset}is analyzing ${green}$i${reset}";
	python ~/programs/LinkFinder/linkfinder.py -i $i -o cli | egrep -v $exc |sort -u | tee -a links;
done;

# links cleasing
echo "${green}[*]${reset}sorting the links"
sort -u links > tmp;
egrep -v $exc tmp > links;
echo "${green}[*]${reset}done with $(wc -l links)";

#file cleansing
rm tmp;
