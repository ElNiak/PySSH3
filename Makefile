# TODO should fix python 3 version, min 3.6
env:
	test -d ssh3_env || python3 -m venv ssh3_env
 
install:
	. ssh3_env/bin/activate && python3 -m pip install wheel && python3 -m pip install .

run-server:
	. ssh3_env/bin/activate && cd py-ssh3 && python3 cli/server/main.py

run-client:
	. ssh3_env/bin/activate && cd py-ssh3 && python3 cli/client/main.py