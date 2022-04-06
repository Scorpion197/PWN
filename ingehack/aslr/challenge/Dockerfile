FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y socat patchelf && \ 
    rm -rf /var/lib/apt/lists/*

RUN useradd aslr 
WORKDIR /home/aslr 

COPY ./flag.txt ./ 
COPY ./chall ./
COPY ./libc.so.6 ./
COPY ./ld-2.31.so ./
COPY ./entrypoint.sh ./

RUN patchelf --set-interpreter ./ld-2.31.so --replace-needed libc.so.6 ./libc.so.6 ./chall
RUN chmod +x entrypoint.sh chall libc.so.6 ld-2.31.so && chown -R aslr:aslr .

USER aslr 

CMD ["./entrypoint.sh"]
