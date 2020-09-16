version = $(shell awk '/^version/' Cargo.toml | head -n1 | cut -d "=" -f 2 | sed 's: ::g')
release := "1"
uniq := $(shell head -c1000 /dev/urandom | sha512sum | head -c 12 ; echo ;)
cidfile := "/tmp/.tmp.docker.$(uniq)"
build_type := release

all:
	mkdir -p build/ && \
	cp Dockerfile.ubuntu20.04 build/Dockerfile && \
	cp -a Cargo.toml src scripts Makefile templates build/ && \
	cd build && \
	docker build -t auth_server_rust/build_rust:ubuntu20.04 . && \
	cd ../ && \
	rm -rf build/

cleanup:
	docker rmi `docker images | python -c "import sys; print('\n'.join(l.split()[2] for l in sys.stdin if '<none>' in l))"`
	rm -rf /tmp/.tmp.docker.auth_server_rust
	rm Dockerfile

package:
	docker run --cidfile $(cidfile) -v `pwd`/target:/auth_server_rust/target auth_server_rust/build_rust:ubuntu20.04 /auth_server_rust/scripts/build_deb_docker.sh $(version) $(release)
	docker cp `cat $(cidfile)`:/auth_server_rust/auth-server-rust_$(version)-$(release)_amd64.deb .
	docker rm `cat $(cidfile)`
	rm $(cidfile)

install:
	cp target/$(build_type)/auth-server-rust /usr/bin/auth-server-rust
	cp target/$(build_type)/auth-server-admin /usr/bin/auth-server-admin

pull:
	`aws ecr --region us-east-1 get-login --no-include-email`
	docker pull 281914939654.dkr.ecr.us-east-1.amazonaws.com/rust_stable:latest
	docker tag 281914939654.dkr.ecr.us-east-1.amazonaws.com/rust_stable:latest rust_stable:latest
	docker rmi 281914939654.dkr.ecr.us-east-1.amazonaws.com/rust_stable:latest
