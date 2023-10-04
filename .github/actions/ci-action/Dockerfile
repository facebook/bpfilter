FROM fedora:38
RUN sudo dnf -y install 'dnf-command(copr)'
RUN sudo dnf -y copr enable naccyde/criterion
RUN sudo dnf -y install \
        clang-tools-extra \
        cmake \
        doxygen \
        git-core \
        lcov \
        libasan \
        libbpf-devel \
        libcmocka-devel \
        libubsan \
        python3-breathe \
        python3-furo \
        python3-sphinx
RUN git clone https://github.com/facebook/bpfilter.git
WORKDIR /bpfilter
RUN cmake -B build -S . -DCMAKE_BUILD_TYPE=release
RUN make -C build
RUN make -C build test
