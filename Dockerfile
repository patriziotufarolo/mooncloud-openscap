FROM repository.internal.moon-cloud.eu:4567/driver-development/mooncloud-driver
ENV openscapversion 1.2.14
WORKDIR /tmp
RUN cat /etc/apt/sources.list | sed s,deb,deb-src, | tee -a /etc/apt/sources.list && \
    apt-get -y update && \
    apt-get -y build-dep openscap && \
    wget https://github.com/OpenSCAP/openscap/releases/download/${openscapversion}/openscap-${openscapversion}.tar.gz && \
    tar -xzpf openscap-${openscapversion}.tar.gz && \
    cd openscap-${openscapversion} && \
    ./configure --libdir /usr/lib --prefix /usr/local && \
    make && \
    make install && \
    cd .. && \
    rm -R /tmp/* && \
    apt-get -y purge $(apt-cache showsrc openscap | sed -e '/Build-Depends/!d;s/Build-Depends: \|,\|([^)]*),*\|\[[^]]*\]//g' -e 's/|//g') && \
    sed -i /^deb-src.*/d /etc/apt/sources.list && \
    apt-get -y update
WORKDIR /usr/src/app
