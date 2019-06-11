sudo insmod network_server.ko io_mode="mmap"
echo "server"
sudo ./master README.md mmap
echo "master"
sudo insmod network_client.ko io_mode="mmap"
echo "client"
sudo ./slave README_slave.md mmap 192.168.50.145
echo "slave"
