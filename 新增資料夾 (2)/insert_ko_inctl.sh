sudo insmod network_server.ko filename="j_ioctl_master" io_mode="fcntl"
echo "server"
sudo ./master README.md fcntl
echo "master"
sudo insmod network_client.ko filename="j_ioctl_slave" io_mode="fcntl"
echo "client"
sudo ./slave README_slave.md fcntl 192.168.50.145
echo "slave"
