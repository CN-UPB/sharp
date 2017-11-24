#!/usr/bin/env bash


apt-get update
apt-get upgrade
apt-get install -y ansible git aptitude
echo 'localhost ansible_connection=local' >> /etc/ansible/hosts

if [! -d "containernet"]; then
	git clone https://github.com/containernet/containernet.git
	cd containernet
	git reset --hard dd40ac4
fi

cd ansible
ansible-playbook install.yml

cd ../..
docker build . -t kuettner/node
docker pull osrg/ryu