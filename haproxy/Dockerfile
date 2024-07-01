FROM haproxy:3.0.2

USER root

RUN apt-get update && \
    apt-get install -y lua5.4 liblua5.4-dev unzip make libssl-dev && \
    apt-get install -y wget && \
    wget https://luarocks.org/releases/luarocks-3.8.0.tar.gz && \
    tar zxpf luarocks-3.8.0.tar.gz && \
    cd luarocks-3.8.0 && \
    ./configure --with-lua-include=/usr/include/lua5.4 && \
    make && \
make install
RUN luarocks install luasocket
RUN luarocks install luaossl
RUN luarocks install LuaSec
RUN luarocks install lua-cjson

USER haproxy

#COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
#COPY jwt_verify.lua /usr/local/etc/haproxy/jwt_verify.lua

#CMD tail -f /dev/null