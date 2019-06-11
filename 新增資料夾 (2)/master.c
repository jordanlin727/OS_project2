#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#define FILE_LENGTH 0x1000
#define BUFFER_SIZE 4096
#include <linux/ioctl.h>
#include <sys/ioctl.h>

//#include "common.h"

#define MAJOR_NUM 121
//#define IOCTL_SET_MSG _IOR(MAJOR_NUM, 0, char *)
//#define IOCTL_GET_MSG _IOR(MAJOR_NUM, 1, char *)
//#define IOCTL_GET_NTH_BYTE _IOWR(MAJOR_NUM, 2, int)
/*
ioctl_set_msg(int file_desc, char *message)
{
	int ret_val;

	ret_val = ioctl(file_desc, IOCTL_SET_MSG, message);

	if (ret_val < 0) {
		printf("ioctl_set_msg failed:%d\n", ret_val);
		exit(-1);
	}
}

ioctl_get_msg(int file_desc)
{
	int ret_val;
	char message[BUFFER_SIZE];


	ret_val = ioctl(file_desc, IOCTL_GET_MSG, message);

	if (ret_val < 0) {
		printf("ioctl_get_msg failed:%d\n", ret_val);
		exit(-1);
	}

	printf("get_msg message:%s\n", message);
}

ioctl_get_nth_byte(int file_desc)
{
	int i;
	char c;

	printf("get_nth_byte message:");

	i = 0;
	do {
		c = ioctl(file_desc, IOCTL_GET_NTH_BYTE, i++);

		if (c < 0) {
			printf
			    ("ioctl_get_nth_byte failed at the %d'th byte:\n",
			     i);
			exit(-1);
		}

		putchar(c);
	} while (c != 0);
	putchar('\n');
}
*/
int main(int argc, char *argv[])
{

    int fd,fd1;
    struct stat sb;
    long page_size;
    char buf[BUFFER_SIZE];
    char buf1[BUFFER_SIZE];
    int ret =0;
    int file_count=0;
    unsigned int start_sec,end_sec;
    long start_nsec, end_nsec;

    char *address1;
    //page_size = sysconf(_SC_PAGE_SIZE);
     if (argc < 3) {
        printf("Usage: %s <file> <method>\n", argv[0]);
        return EXIT_FAILURE;
    }
    page_size = getpagesize();
    // open read file
    fd = open(argv[1], O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open");
        //assert(0);
    }
    if (stat(argv[1], &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    /*
    fd1 = open("/proc/modules", O_RDONLY );
    if (fd1>0)
    {
        read(fd1,buf1,BUFFER_SIZE);


        //printf("buf1=%s,len=%d\n",buf1,strlen(buf1));

        if (strstr("network_server",buf1) == NULL)
        {
            //printf("CHECK\n");
            snprintf(buf,sizeof(buf), "sudo insmod network_server.ko io_mode=\"%s\"", argv[2]);
            system(buf);
        }
        else
        {
            printf("???\n");
        }
        close(fd1);
    }
    */
    snprintf(buf,sizeof(buf), "sudo rmmod network_server");
    system(buf);
    snprintf(buf,sizeof(buf), "sudo insmod network_server.ko io_mode=\"%s\"", argv[2]);
    system(buf);
    if(strstr(argv[2],"mmap")!=NULL)
    {
        printf("file size=%ld\n",sb.st_size);
        fd1 = open("/proc/j_mmap_master", O_RDWR );
        address1 = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
        if (address1 == MAP_FAILED) {
            perror("mmap");
            //assert(0);

        }

        file_count = sb.st_size;
        while(file_count>0)
        {
            memset(&buf,0,BUFFER_SIZE);
            ret = read(fd, buf, BUFFER_SIZE);//fd to buffer

            write(fd1, buf, ret);// buffer to fd1
            file_count -= ret;
        }
        //read(fd1, buf1, sb.st_size);// fd1 to buffer, transmit to mmap read
        if (munmap(address1, page_size))
        {
            perror("munmap");
            //assert(0);
        }
        //printf("string =%s\n",buf1);


    }
    else
    {
        printf("file size=%ld\n",sb.st_size);
        //system("sudo rm /dev/j_ioctl_master");
        //system("sudo mknod /dev/j_ioctl_master c 121 0");

        fd1 = open("/dev/j_ioctl_master",  O_RDONLY);
        if (fd1<0)
        {
            system("sudo mknod /dev/j_ioctl_master c 121 0");
        }
        else
        {
            close(fd1);
        }

        //char *msg = "Message passed by ioctl\n";
        fd1 = open("/dev/j_ioctl_master", O_RDWR );
        if (fd1 < 0) {
		printf("Can't open device file: %s\n", "j_ioctl_master");
		exit(-1);
	    }
	    //printf("len=%d\n",strlen(msg));
	    file_count = sb.st_size;
        while(file_count>0)
        {
	        ret = read(fd,buf, BUFFER_SIZE);
	        write(fd1, buf, sb.st_size);
	        file_count -= ret;
	    }
	    //write(fd1,msg,strlen(msg));
	    //ioctl_get_nth_byte(fd1);
	    //ioctl_set_msg(fd1, msg);
	    //ioctl_get_msg(fd1);
	    //ioctl_set_msg(fd1, msg);
	    //ioctl_get_nth_byte(fd1);
    }
    close(fd);
    close(fd1);
    exit(0);
}
