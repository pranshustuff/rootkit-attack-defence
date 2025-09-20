#!/bin/bash
DAEMON=/usr/local/bin/hellod   # compiled binary location
PIDFILE=/var/run/hello_daemon.pid
[ -r "$PIDFILE" ] || PIDFILE=/tmp/hello_daemon.pid  # fallback

start() {
    echo "Starting hello_daemon..."
    sudo $DAEMON
}

stop() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat $PIDFILE)
        echo "Stopping hello_daemon (PID $PID)..."
        sudo kill -TERM $PID
        sleep 1
        [ -f "$PIDFILE" ] && sudo rm -f $PIDFILE
    else
        echo "No PID file found."
    fi
}

status() {
    if [ -f "$PIDFILE" ]; then
        PID=$(cat $PIDFILE)
        if ps -p $PID > /dev/null 2>&1; then
            echo "hello_daemon is running (PID $PID)."
        else
            echo "PID file exists but process not running."
        fi
    else
        echo "hello_daemon is not running."
    fi
}

case "$1" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    restart) stop; start ;;
    *) echo "Usage: $0 {start|stop|status|restart}" ;;
esac
