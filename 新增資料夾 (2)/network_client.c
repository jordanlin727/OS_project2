#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>

#include <linux/stat.h>

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#include <linux/ioctl.h>

#define PORT_NUMBER 6666
//static char *filename = NULL;
//static char *filename = "README.md";
static char *filename = "j_mmap_slave";
module_param(filename, charp, 0000);
//static char *io_mode = NULL;
//static char *io_mode = "fcntl";
static char *io_mode = "mmap";
module_param(io_mode, charp, 0000);
static char *ip_address = "192.168.50.145";
//static char *ip_address = NULL;
module_param(ip_address, charp, 0000);
struct socket *conn_socket = NULL;
#define MAX_PACKET_SIZE 4096
static char transmit_buff[MAX_PACKET_SIZE];
static int transmit_len;
#define MAJOR_NUM 122
static int Device_Open = 0;
static char *Message_Ptr;
//static char Message_Ptr[MAX_PACKET_SIZE];
static char Message[MAX_PACKET_SIZE];
enum { BUFFER_SIZE = 4 };

struct mmap_info {
    char *data;
};

/* After unmap. */
static void vm_close(struct vm_area_struct *vma)
{
    //printk("vm_close\n");
    ;
}

/* First page access. */
static int vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    struct page *page;
    struct mmap_info *info;

    //printk("vm_fault\n");
    info = (struct mmap_info *)vma->vm_private_data;
    if (info->data) {
        page = virt_to_page(info->data);
        get_page(page);
        vmf->page = page;
    }
    return 0;
}

/* Aftr mmap. TODO vs mmap, when can this happen at a different time than mmap? */
static void vm_open(struct vm_area_struct *vma)
{
    //printk("client: vm_open\n");
    ;
}

static struct vm_operations_struct vm_ops =
{
    .close = vm_close,
    .fault = vm_fault,
    .open = vm_open,
};

static int mmap(struct file *filp, struct vm_area_struct *vma)
{
    //printk("client: mmap\n");
    vma->vm_ops = &vm_ops;
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_private_data = filp->private_data;
    vm_open(vma);
    return 0;
}

static int open(struct inode *inode, struct file *filp)
{
    struct mmap_info *info;

    //printk("client: MMAP_open\n");
    info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
    //printk("virt_to_phys = 0x%llx\n", (unsigned long long)virt_to_phys((void *)info));
    printk("client: virt_to_phys = %x\n", (unsigned long long)virt_to_phys((void *)info));
    info->data = (char *)get_zeroed_page(GFP_KERNEL);
    //memcpy(info->data, "stephen", BUFFER_SIZE);
    filp->private_data = info;
    return 0;
}

static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    struct mmap_info *info;
    int ret;

    //printk("client: MMAP_read\n");
    info = filp->private_data;
    //printk("len=%d \n, buffer =%s\n", transmit_len, transmit_buff);
    //copy tcp buffer to file
    memcpy(info->data, transmit_buff, transmit_len);
    //ret = min(len, (size_t)BUFFER_SIZE);
    //ret = min(len, (size_t)MAX_PACKET_SIZE);
    ret = min(len, (size_t)transmit_len);
    if (copy_to_user(buf, info->data, ret)) {
        ret = -EFAULT;
    }
    //memset(&transmit_buff, 0, MAX_PACKET_SIZE);
    //strcat(transmit_buff, buf);
    return ret;
}

static ssize_t write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    struct mmap_info *info;

    //printk("client: MMAP_write\n");
    info = filp->private_data;

    //if (copy_from_user(info->data, buf, min(len, (size_t)BUFFER_SIZE))) {
    if (copy_from_user(info->data, buf, min(len, (size_t)MAX_PACKET_SIZE))) {
        return -EFAULT;
    } else {
        return len;
    }
}

static int release(struct inode *inode, struct file *filp)
{
    struct mmap_info *info;

    //printk("client: MMAP_release\n");
    info = filp->private_data;
    free_page((unsigned long)info->data);
    kfree(info);
    filp->private_data = NULL;
    return 0;
}

static const struct file_operations fops = {
    .mmap = mmap,
    .open = open,
    .release = release,
    .read = read,
    .write = write,
};


// ioctl
static int device_open(struct inode *inode, struct file *file)
{
	printk(KERN_INFO "client : device_open(%p)\n", file);

	if (Device_Open)
		return -EBUSY;

	Device_Open++;
    inode->i_private = inode;
    file->private_data = file;
	Message_Ptr = Message;
	try_module_get(THIS_MODULE);
	return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
	//printk(KERN_INFO "client : device_release(%p,%p)\n", inode, file);

	Device_Open--;

	module_put(THIS_MODULE);
	return 0;
}

static ssize_t device_read(struct file *file, char __user * buffer, size_t length, loff_t * offset)
{
	int bytes_read = 0;

	//printk(KERN_INFO "client : device_read(%p,%p,%d)\n", file, buffer, length);

    int ret;
    ret = transmit_len;
	if (*Message_Ptr == 0)
    /*
	while (length && *Message_Ptr) {

		put_user(*(Message_Ptr++), buffer++);
		length--;
		bytes_read++;
	}
    */

    if (copy_to_user(buffer, transmit_buff, ret)) {
        ret = -EFAULT;
    }
    bytes_read = ret;

	//printk(KERN_INFO "client : Read %d bytes, %d left\n", ret, length);


	return bytes_read;
}

static ssize_t
device_write(struct file *file, const char __user * buffer, size_t length, loff_t * offset)
{
	int i;

	//printk(KERN_INFO "client : device_write(%p,%s,%d)\n", file, buffer, length);

    //printk("length=%lu\n",length);
	//for (i = 0; i < length && i < BUF_LEN; i++)
	for (i = 0; i < length && i < MAX_PACKET_SIZE; i++)
		get_user(Message[i], buffer + i);

	Message_Ptr = Message;
    memset(&transmit_buff, 0, MAX_PACKET_SIZE);
    strcat(transmit_buff, Message);
	return i;
}

/*
int device_ioctl(struct inode *inode, struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
	int i;
	char *temp;
	char ch;


	switch (ioctl_num) {
	case IOCTL_SET_MSG:

		temp = (char *)ioctl_param;

		get_user(ch, temp);
		//for (i = 0; ch && i < BUF_LEN; i++, temp++)
		for (i = 0; ch && i < MAX_PACKET_SIZE; i++, temp++)
			get_user(ch, temp);

		device_write(file, (char *)ioctl_param, i, 0);
		break;

	case IOCTL_GET_MSG:

		i = device_read(file, (char *)ioctl_param, 99, 0);

		put_user('\0', (char *)ioctl_param + i);
		break;

	case IOCTL_GET_NTH_BYTE:

		return Message[ioctl_param];
		break;
	}

	return 0;
}
*/
struct file_operations Fops = {
    .owner =  THIS_MODULE,
	.read = device_read,
	.write = device_write,
	//.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_release,
};

u32 create_address(u8 *ip)
{
    u32 addr = 0;
    int i;

    for(i=0; i<4; i++)
    {
        addr += ip[i];
        if(i==3)
            break;
        addr <<= 8;
    }
    return addr;
}

int tcp_client_send(struct socket *sock, const char *buf, const size_t length, unsigned long flags)
{
    struct msghdr msg;
    //struct iovec iov;
    struct kvec vec;
    int len, written = 0, left = length;
    mm_segment_t oldmm;

    msg.msg_name    = 0;
    msg.msg_namelen = 0;
    /*
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    */
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags   = flags;

    oldmm = get_fs(); set_fs(KERNEL_DS);
repeat_send:
    /*
    msg.msg_iov->iov_len  = left;
    msg.msg_iov->iov_base = (char *)buf + written;
    */
    vec.iov_len = left;
    vec.iov_base = (char *)buf + written;

    //len = sock_sendmsg(sock, &msg, left);
    len = kernel_sendmsg(sock, &msg, &vec, left, left);
    if((len == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) && (len == -EAGAIN)))
        goto repeat_send;
    if(len > 0)
    {
        written += len;
        left -= len;
        if(left)
            goto repeat_send;
    }
    set_fs(oldmm);
    return written ? written:len;
}

int tcp_client_receive(struct socket *sock, char *str, unsigned long flags)
{
    //mm_segment_t oldmm;
    struct msghdr msg;
    //struct iovec iov;
    struct kvec vec;
    int len;
    int max_size = MAX_PACKET_SIZE;

    msg.msg_name    = 0;
    msg.msg_namelen = 0;
    /*
    msg.msg_iov     = &iov;
    msg.msg_iovlen  = 1;
    */
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags   = flags;
    /*
    msg.msg_iov->iov_base   = str;
    msg.msg_ioc->iov_len    = max_size;
    */
    vec.iov_len = max_size;
    vec.iov_base = str;

    //oldmm = get_fs(); set_fs(KERNEL_DS);
read_again:
    //len = sock_recvmsg(sock, &msg, max_size, 0);
    len = kernel_recvmsg(sock, &msg, &vec, max_size, max_size, flags);

    if(len == -EAGAIN || len == -ERESTARTSYS)
    {
        printk("client receive error\n");

        goto read_again;
    }

    //printk("client receive message from server len=%d \n%s\n", len, str);
    strcat(transmit_buff, str);
    transmit_len = len;

    //set_fs(oldmm);
    return len;
}
int readFile(struct file *fp,char *buf,int readlen)
{
    if (fp->f_op && fp->f_op->read)
    {
        return fp->f_op->read(fp,buf,readlen, &fp->f_pos);
    }
    else
    {
        printk("failed\n");
        return -1;
    }
}
//設定帳號跟密碼並傳送資料
int tcp_client_connect(char* ipstring)
{
    struct sockaddr_in saddr;
    /*
    struct sockaddr_in daddr;
    struct socket *data_socket = NULL;
    */
    int ret = -1;
    #if 0
    // ============= open and read file ===============
    struct file *fp, *fp1;
    static char buf[1024];
    struct kstat file_buf;
    loff_t pos=0;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    //set_fs(get_ds());
    //printk("filestring=%s\n", filestring);
    fp=filp_open(filestring, O_RDONLY, 0644);
    fp1=filp_open("README1.md", O_RDWR | O_CREAT, 0644);
    //fp=filp_open("/home/user/nfs/project2/README.md", O_RDONLY, 0);
    //fp=filp_open("/home/user/nfs/project2/README.md", O_RDONLY | O_CREAT, 0644);
    vfs_stat(fp, &file_buf);
    if (fp!=NULL)
    {
        memset(buf,0,1024);
        ssize_t test;
        test=vfs_read(fp,buf, sizeof(buf), &pos);
        pos = fp1->f_pos;
        //printk("file size=%lld\n",file_buf.size);

        vfs_write(fp1,buf, test, &pos);
        fp->f_pos = pos;
        vfs_fsync(fp1,0);
        filp_close(fp1,NULL);
        filp_close(fp,NULL);
        set_fs(oldfs);
    }
    #endif
    // ============== open and read file ===========
    unsigned char destip[5] = {192,168,50,145,'\0'};
    /*
    if (ipstring != NULL)
    {
        printk("ip string!=NULL\n");
        snprintf(destip, sizeof(destip), "%s", ipstring);
        destip[4]='\0';
    }
    */
    /*
    char *response = kmalloc(4096, GFP_KERNEL);
    char *reply = kmalloc(4096, GFP_KERNEL);
    */
    int len = MAX_PACKET_SIZE - 1;
    char response[len+1];
    char reply[len+1];
    ret = -1;

    //DECLARE_WAITQUEUE(recv_wait, current);
    DECLARE_WAIT_QUEUE_HEAD(recv_wait);

    ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &conn_socket);
    if(ret < 0)
    {
        //printk("client socket create error");
        goto err;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(PORT_NUMBER);
    saddr.sin_addr.s_addr = htonl(create_address(destip));

    ret = conn_socket->ops->connect(conn_socket, (struct sockaddr *)&saddr\
                    , sizeof(saddr), O_RDWR);
    if(ret && (ret != -EINPROGRESS))
    {
            //printk("client connect error\n");
            goto err;
    }
    struct timespec start_time;
    struct timespec end_time;
    struct timeval begin, end;
    memset(&reply, 0, len+1);
    strcat(reply, "START");



    tcp_client_send(conn_socket, reply, strlen(reply), MSG_DONTWAIT);

    wait_event_timeout(recv_wait, !skb_queue_empty(&conn_socket->sk->sk_receive_queue), 5*HZ);
    do_gettimeofday(&begin);
    getnstimeofday(&start_time);
    if(!skb_queue_empty(&conn_socket->sk->sk_receive_queue))
    {
        /*
        __set_current_status(TASK_RUNNING);
        remove_wait_queue(&conn_socket->sk->sk_wq->wait,\
                                              &recv_wait);
        */
        memset(&response, 0, len+1);

        tcp_client_receive(conn_socket, response, MSG_DONTWAIT);
        getnstimeofday(&end_time);
        do_gettimeofday(&end);
        //if((end_time.tv_sec -start_time.tv_sec)!=0)
        if((end.tv_sec - begin.tv_sec)!=0)
        {

            //printk("end=%d\n",end.tv_sec);
            //printk("begin=%d\n",begin.tv_sec);
            //int temp = (end_time.tv_sec - start_time.tv_sec);
            int temp = (end.tv_sec - begin.tv_sec);
            //printk("temp=%d\n",temp);

            printk("Transmission time: 0.%.6lu ms, File size: %d bytes\n", (end_time.tv_nsec-start_time.tv_nsec)/1000, transmit_len);
            //printk("Transmission time: %12d ms, File size: %d bytes\n", (unsigned int)(end.tv_usec-begin.tv_usec), transmit_len);
        }
        else
            printk("Transmission time: 0.%.6lu ms, File size: %d bytes\n", (end_time.tv_nsec-start_time.tv_nsec)/1000, transmit_len);
            //printk("Transmission time: 0.%.3lu ms, File size: %d bytes\n", (unsigned int)(end.tv_usec-begin.tv_usec), transmit_len);
        //break;
    }

    /*
    }
    */

err:
    return -1;
}

static int __init network_client_init(void)
{
    //initial 的時候執行 tcp_client_connect()
    //printk("client init \n");
    //printk(KERN_ALERT "filename:%s\n", filename);

    tcp_client_connect(ip_address);
    if (strstr(io_mode,"fcntl")!=NULL)
    {
        int ret =0;
        ret = register_chrdev(MAJOR_NUM, "j_ioctl_slave", &Fops);
    }
    else
    {
        proc_create("j_mmap_slave", 0, NULL, &fops);

    }
    return 0;
}

static void __exit network_client_exit(void)
{
    int len = MAX_PACKET_SIZE -1 ;
    char response[len+1];
    char reply[len+1];

    //DECLARE_WAITQUEUE(exit_wait, current);
    DECLARE_WAIT_QUEUE_HEAD(exit_wait);

    memset(&reply, 0, len+1);
    strcat(reply, "END");
    //tcp_client_send(conn_socket, reply);
    tcp_client_send(conn_socket, reply, strlen(reply), MSG_DONTWAIT);
    //while(1)
    //{
            /*
            tcp_client_receive(conn_socket, response);
            add_wait_queue(&conn_socket->sk->sk_wq->wait, &exit_wait)
            */
     wait_event_timeout(exit_wait, !skb_queue_empty(&conn_socket->sk->sk_receive_queue), 5*HZ);
    if(!skb_queue_empty(&conn_socket->sk->sk_receive_queue))
    {
        memset(&response, 0, len+1);
        tcp_client_receive(conn_socket, response, MSG_DONTWAIT);
            //remove_wait_queue(&conn_socket->sk->sk_wq->wait, &exit_wait);
    }

    //}

    if(conn_socket != NULL)
    {
        sock_release(conn_socket);
    }
    if (strstr(io_mode,"fcntl")==NULL)
        remove_proc_entry("j_mmap_slave", NULL);
    else
        unregister_chrdev(MAJOR_NUM, "j_ioctl_slave");
    //printk("client exit\n");
}

module_init(network_client_init)
module_exit(network_client_exit)
