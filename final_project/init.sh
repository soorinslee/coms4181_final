#!/bin/bash

users=("addleness" "analects" "annalistic" "anthropomorphologically" "blepharosphincterectomy" "corector" "durwaun" "dysphasia" "encampment" "endoscopic" "exilic" "forfend" "gorbellied" "gushiness" "muermo" "neckar" "outmate" "outroll" "overrich" "philosophicotheological" "pockwood" "polypose" "refluxed" "reinsure" "repine" "scerne" "starshine" "unauthoritativeness" "unminced" "unrosed" "untranquil" "urushinic" "vegetocarbonaceous" "wamara" "whaledom")

passwords=("Cardin_pwns" "pickerel_symbiosis" "thickets_pimping" "likelihoods_hoarsely" "plagued_teletypewriter" "quadruplet_strawed" "hamlet_laudably" "equably_undies" "Noxzema's_wordiness" "centennial's_subplots" "service_barbing" "Tammy's_hoofed" "pinfeathers_Finnbogadottir's" "Cameroon's_adaptations" "grovelling_turtle" "simmering_Caucasian's" "gush's_Colombia" "carpus's_hazardous" "Freemasonry_bruskest" "lopsided_garishly" "Borges's_helpful" "lure_leagued" "brushed_volubly" "Hammett_Biden's" "tallyho's_courage" "fucks_allured" "soul's_blondes" "officially_watershed" "cleaves_refund" "shamed_Dow" "bespoke_supplants" "ramble_tiller's" "channelled_inexpressible" "stirrer_hewer's" "petering_sounding's")


mkdir server
mkdir clients

cd server

mkdir certs
mkdir passwords
mkdir messages

cd certs

for i in ${users[@]}
do
	mkdir $i

done

cd ..
cd messages

for i in ${users[@]}
do
	mkdir $i

done
cd ..
cd passwords

## get length of $distro array
len=${#users[@]}
 
## Use bash for loop 
for (( i=0; i<$len; i++ ))
do 
	#your_command_string="./hashpassword ${#passwords[@]}"
	#output=$(eval "$your_command_string")
	../../hashpassword ${passwords[$i]} > ${users[$i]}.pwd
	#echo $?
	#echo "$?" >> ${users[$i]}.pwd

done

cd ..
cd ..

cd clients

for i in ${users[@]}
do
	mkdir $i
	cd $i
	mkdir keys
	mkdir certs
	mkdir csr 
	cp ../../getcert getcert
	cp ../../changepw changepw
	cd ..

done