# bpf-build is docker name
work_path=$(pwd)
docker exec -it bpf-build sh -c  "cd $work_path;make BPF_CORE_SRC=$1 OUTPUT=$2"
