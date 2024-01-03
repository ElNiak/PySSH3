# TODO should fix python 3 version, min 3.6
env:
	test -d ssh3_env || python3 -m venv ssh3_env
 
install:
	. ssh3_env/bin/activate && python3 -m pip install wheel && cd py-ssh3/aioquic/ && python3 -m pip install . && cd ../../ && python3 -m pip install .
