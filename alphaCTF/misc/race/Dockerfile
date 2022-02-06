FROM ubuntu:20.04 

RUN apt-get update -y 
RUN apt-get install socat -y 

RUN useradd -m -d /home/race -s /bin/bash -u 1000 race 

WORKDIR /home/race 

COPY ./chall ./ 
COPY ./entrypoint.sh ./ 

RUN chmod 777 /home/race 
RUN chmod +x ./entrypoint.sh 
RUN chmod +x ./chall 

EXPOSE 9010

CMD ["./entrypoint.sh"]


