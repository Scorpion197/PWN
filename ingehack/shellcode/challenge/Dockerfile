FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y socat && \
    rm -rf /var/lib/apt/lists 

RUN useradd shellcode 

WORKDIR /home/shellcode/secret_flag_197 
COPY ./flag_14723453822146942958.txt ./

WORKDIR /home/shellcode

COPY ./chall ./
COPY ./entrypoint.sh ./

RUN chmod +x entrypoint.sh chall && chown -R shellcode:shellcode .

USER shellcode

CMD ["./entrypoint.sh"]

