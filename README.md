# sharp
Seamless Handover Protocol (SHarP)

### Installation
* Requires: Ubuntu **16.04 LTS**

The installation is utilizes the [containernet](https://github.com/containernet/containernet/) Ansible playbook.
This version of SHarP is based on a specific containernet version.

```bash
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install ansible git aptitude
git clone https://github.com/containernet/containernet.git
cd containernet
git reset ----hard dd40ac4
cd ansible
sudo ansible-playbook -i "localhost" -c local install.yml
cd ../..
docker build . -t sharp/node
docker pull osrg/ryu
```

### Usage / Run
Start a multi-handover evaluation. The results will autmatically be saved in `evaluation-results`.

```bash
sudo su
export PYTHONPATH=`pwd`
cd handover/evaluation
python evaluation_tests.py
```

Run `python evaluation_tests.py --help` for additional command line parameters

#### Manually execute a handover
To follow the execution of one or more handovers in detail all components of the
system have to be started separately.

```bash
sudo sudo
export PYTHONPATH=`pwd`
./start_controller.sh
python handover/run/register_default.py
./start_network.sh
```
The network is now set up with two hosts connected via `VNF1`.
Next we start the UDP traffic generator to generate traffic between two hosts.
```bash
docker exec -it mn.d1 generator -r 100 -s 500 10.0.0.102
```
Now we can start a test script that adds rules with increasing priority.
```bash
python handover/run/start_handover_toggling.py
```