.PHONY: start run

start:
	@if [ ! -d "pox" ]; then git clone https://github.com/noxrepo/pox.git; fi
	@mkdir -p $(HOME)/.config
	@if [ ! -e "$(HOME)/.config/nvim" ]; then git clone https://github.com/TimB44/nvim-config $(HOME)/.config/nvim; fi

run: start
	cp ./ctr.py ./pox/ext/
	cd pox && python pox.py openflow.of_01 --port=6633 ctl
