build:
	cd $(BUILD) && \
	./autogen.sh && \
	./configure --prefix=$(SDE_INSTALL) --with-tofino P4_NAME=knet_mgr_test P4_PATH=$(SRC)/knet_mgr_test/knet_mgr_test.p4 --enable-thrift && \
	make clean && \
	make && \
	make install
run:
	/root/bf-sde-8.2.0/run_switchd.sh -p knet_mgr_test
push:
	git add -A
	git commit -m "Automatic uploading. No comments!"
	git push
pull:
	git pull
register:
	python ReadRegister.py
send:
	python SendPacket.py
test: test.cc
	g++ test.cc -o test
	./test
ptf:
	/root/bf-sde-8.2.0/run_p4_tests.sh -p knet_mgr_test
