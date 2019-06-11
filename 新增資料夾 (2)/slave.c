#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#define FILE_LENGTH 0x1000
#define BUFFER_SIZE 4096
#define MAJOR_NUM 122
static void set_ipaddr(const char *dev, const char *ip)
{
    int sfd, saved_errno, ret;
    struct ifreq ifr;
    struct sockaddr_in sin;
    sfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &(sin.sin_addr));
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
    errno = saved_errno;
    ret = ioctl(sfd, SIOCSIFADDR, &ifr);
    if (ret == -1)
    {
        if (errno == 19)
        {
            fprintf(stderr, "Interface %s : No such device.\n", dev);
            exit(EXIT_FAILURE);
        }
        if (errno == 99)
        {
            fprintf(stderr, "Interface %s : No IPv4 address assigned.\n", dev);
            exit(EXIT_FAILURE);
        }
    }
    saved_errno = errno;
    close(sfd);
}
int main(int argc, char *argv[])
{

    int fd,fd1;
    //struct stat sb;
    long page_size;
    char buf[BUFFER_SIZE];
    char buf1[BUFFER_SIZE];
    char *address1;
    int ret =0;
    int file_count=0;

    //page_size = sysconf(_SC_PAGE_SIZE);
     if (argc < 4) {
        printf("Usage: %s <file> <method> <IP>\n", argv[0]);
        return EXIT_FAILURE;
    }
    page_size = getpagesize();
    fd = open(argv[1], O_RDONLY);
    if(fd)
    {
        close(fd);
        unlink(argv[1]);
        system("sync");
    }

    set_ipaddr("enp0s3", argv[3]);

    fd = open(argv[1], O_RDWR | O_CREAT |O_SYNC);
    if (fd < 0) {
        perror("open");
        //assert(0);
    }
    /*
    fd1 = open("/proc/modules", O_RDONLY );
    if (fd1>0)
    {
        read(fd1,buf1,BUFFER_SIZE);
        if (strstr("network_client",buf1)==NULL)
        {
            //printf("CHECK\n");
            snprintf(buf,sizeof(buf), "sudo insmod network_client.ko io_mode=\"%s\"", argv[2]);
            system(buf);
        }
        close(fd1);

    }*/
    snprintf(buf,sizeof(buf), "sudo rmmod network_client");
    system(buf);
    snprintf(buf,sizeof(buf), "sudo insmod network_client.ko io_mode=\"%s\"", argv[2]);
    system(buf);
    printf("start slave\n");
    if(strstr(argv[2],"mmap")!=NULL)
    {
        //printf("size=%ld\n",sb.st_size);
        fd1 = open("/proc/j_mmap_slave", O_RDWR );
        address1 = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
        if (address1 == MAP_FAILED) {
            perror("mmap");
            //assert(0);
        }

        ret = read(fd1, buf, BUFFER_SIZE); // read from mmap
        printf("slave size=%d\n", ret);
        write(fd, buf, ret); // write to file

        //read(fd1, buf1, sb.st_size);

        if (munmap(address1, page_size))
        {
            perror("munmap");
            //assert(0);
        }
        //printf("string =%s\n",buf1);
        close(fd);
        close(fd1);
        snprintf(buf1, sizeof(buf1), "sudo chown user:user %s", argv[1]);
        system(buf1);
        snprintf(buf1, sizeof(buf1), "sudo chmod 664 %s", argv[1]);
        system(buf1);

    }
    else
    {
        //system("sudo mknod /dev/j_ioctl_slave c 122 0");
        //system("sudo mknod /dev/j_ioctl_slave c 122 0");
        fd1 = open("/dev/j_ioctl_slave",  O_RDONLY);
        if (fd1<0)
        {
            system("sudo mknod /dev/j_ioctl_slave c 122 0");
        }
        else
        {
            close(fd1);
        }

        fd1 = open("/dev/j_ioctl_slave", O_RDWR );
        if (fd1 < 0) {
		    printf("Can't open device file: %s\n", "j_ioctl_slave");
		    exit(-1);
	    }

	    ret = read(fd1, buf, BUFFER_SIZE); // read from mmap
        printf("slave size=%d\n", ret);
        write(fd, buf, ret); // write to file
	    close(fd);
        close(fd1);
        snprintf(buf1, sizeof(buf1), "sudo chown user:user %s", argv[1]);
        //printf("buf1=%s\n",buf1);
        system(buf1);
        snprintf(buf1, sizeof(buf1), "sudo chmod 664 %s", argv[1]);
        //printf("buf1=%s\n",buf1);
        system(buf1);
    }
    exit(0);
}
