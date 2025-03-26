.PHONY: start run

start:
	@if [ ! -d "pox" ]; then git clone https://github.com/noxrepo/pox.git; fi
	sudo apt-get install mininet
	sudo apt install neovim
	cd ~ && git clone https://github.com/mininet/mininet && mininet/util/install.sh -w


run: 
	cp ./load_balancer.py ./pox/ext/
	cd pox && python3 pox.py openflow.of_01 --port=6633 load_balancer

run-mn:
	sudo mn --topo single,6 --mac --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow10
