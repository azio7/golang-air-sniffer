out_dir = ./bin/
build:
		go build -o $(out_dir) .
release:
		go build -o $(out_dir)-ldflags -w .