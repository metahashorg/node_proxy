#!/bin/bash

workdir=/opt/proxy
port=9999
num=1000000
log=proxy.log
key=proxy_key
conf=proxy.conf

function startProxy() {

    status
    if [ $res -eq 0 ]
    then
        echo Proxy already running, pid $pid
    else
        ulimit -c unlimited
        if [ -d $workdir ]
        then
           cd $workdir

           if [ ! -f $key ]
           then
               echo "No key file $key found, exiting."
               exit 2
           elif [ ! -f $conf ]
           then
               echo "No config file $conf found, exiting."
                          exit 2
           fi
           echo Staring proxy
           ./proxy $key $conf $port $num > $log &
        else
           echo "workdir $workdir doesn't exists"
           exit 2;
        fi
    fi


}


function stopProxy() {


    status
    if [ $res -ne 0 ]
       then
               echo Proxy not running
    else

        echo Stopping proxy, pid $pid
        kill $pid
        status

        if [ $res -eq 0 ]
        then
            echo Stop failed. Proxy still alive, pid $pid. Please check manually
        fi

    fi
}

function status() {

    pid=`pidof proxy`
    res=$?
}


case "$1" in
start)
    startProxy
    ;;

stop)
    stopProxy
    ;;

restart)
    stopProxy
    startProxy
    ;;

status)
     status

    if [ $res -ne 0 ]
       then
               echo -e "Proxy \e[31mnot running\e[0m"
       else
               echo -e "Proxy is \e[32mrunning\e[0m. Pid $pid"
       fi
     ;;

 *)
     echo "Usage: $0 start|stop|status|restart"
     exit 1
    ;;
esac
