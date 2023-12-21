env:
	python3.6 -m venv ssh3_env
	source ssh3_env/bin/activate

install:
	deactivate
	source ssh3_env/bin/activate
	python3.6 -m pip pip install .
