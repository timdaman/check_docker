
good_container() {
    docker run -d --name good_sleep busybox sleep 1d
}

bad_container() {
    docker run -d --name bad_sleep busybox false
}

current_container() {
    docker pull busybox:latest
    docker run -d --name current_container busybox:latest sleep 1d
}

old_container() {
    docker pull busybox:1.28.1
    docker tag busybox:1.28.1 busybox:latest
    docker rmi busybox:1.28.1
    docker run -d --name old_container busybox:latest sleep 1d
}


crashing_container() {
    docker run -d --name crashes --restart always busybox false
}

get_check_docker_version() {
    pip3 show check_docker 2>/dev/null | sed -n '/^Version: /s/^Version: //p'
}