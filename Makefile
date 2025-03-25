.PHONY: start run

start:
	@if [ ! -d "pox" ]; then git clone https://github.com/noxrepo/pox.git; fi
	@mkdir -p $(HOME)/.config
	@if [ ! -e "$(HOME)/.config/nvim" ]; then git clone https://github.com/TimB44/nvim-config $(HOME)/.config/nvim; fi

run: start
	cp ./load_balancer.py ./pox/ext/
	cd pox && python pox.py openflow.of_01 --port=6633 ctl

run-mn:
	sudo mn --topo single,6 --mac --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow10
