#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
// system call
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/stat.h>
// system call

#include <linux/errno.h>
#include <linux/types.h>

#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <linux/unistd.h>
#include <linux/wait.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/request_sock.h>

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

#include <linux/ioctl.h>
//#include "common.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("J");

#define PORT_NUMBER 6666
//static char *filename = NULL;
static char *filename = "j_mmap_master";
module_param(filename, charp, 0000);
//static char *io_mode = NULL;
//static char *io_mode = "fcntl";
static char *io_mode = "mmap";
module_param(io_mode, charp, 0000);
#define MAXIMUM_CONNECTION 10
#define MAX_PACKET_SIZE 4096
static int listener_stop = 0;
static int tcp_acceptor_stopped = 0;
static char *Message_Ptr;
//static char Message_Ptr[MAX_PACKET_SIZE];
static char Message[MAX_PACKET_SIZE];

#define MAJOR_NUM 121
//#define IOCTL_SET_MSG _IOR(MAJOR_NUM, 0, char *)
//#define IOCTL_GET_MSG _IOR(MAJOR_NUM, 1, char *)
//#define IOCTL_GET_NTH_BYTE _IOWR(MAJOR_NUM, 2, int)

static int Device_Open = 0;
//struct file *fp;
//ssize_t test=0;
//loff_t pos=0;
/*
struct file *fp=NULL;
static char buf[1024];
struct kstat file_buf;
    loff_t pos=0;
    mm_segment_t oldfs;
*/
DEFINE_SPINLOCK(tcp_server_lock);
static char transmit_buff[MAX_PACKET_SIZE];

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
    //printk("vm_open\n");
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
    //printk("mmap\n");
    vma->vm_ops = &vm_ops;
    vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_private_data = filp->private_data;
    vm_open(vma);
    return 0;
}

static int open(struct inode *inode, struct file *filp)
{
    struct mmap_info *info;

    //printk("MMAP_open\n");
    info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
    //printk("virt_to_phys = 0x%llx\n", (unsigned long long)virt_to_phys((void *)info));
    printk("server: virt_to_phys = %x\n", (unsigned long long)virt_to_phys((void *)info));
    info->data = (char *)get_zeroed_page(GFP_KERNEL);
    //memcpy(info->data, "stephen", BUFFER_SIZE);
    filp->private_data = info;
    return 0;
}

static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    struct mmap_info *info;
    int ret;

    //printk("MMAP_read\n");
    info = filp->private_data;
    //ret = min(len, (size_t)BUFFER_SIZE);
    ret = min(len, (size_t)MAX_PACKET_SIZE);
    if (copy_to_user(buf, info->data, ret)) {

        ret = -EFAULT;
        //printk("ret=%d\n",ret);
    }
    memset(&transmit_buff, 0, MAX_PACKET_SIZE);
    strcat(transmit_buff, buf);
    return ret;
}

static ssize_t write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    struct mmap_info *info;

    //printk("server :MMAP_write\n");
    info = filp->private_data;
    memset(&transmit_buff, 0, MAX_PACKET_SIZE);
    //if (copy_from_user(info->data, buf, min(len, (size_t)BUFFER_SIZE))) {
    if (copy_from_user(info->data, buf, min(len, (size_t)MAX_PACKET_SIZE))) {
        return -EFAULT;
    }
    strcat(transmit_buff, buf);
    //printk("len=%d\n",len);
    return len;

}

static int release(struct inode *inode, struct file *filp)
{
    struct mmap_info *info;

    //printk("MMAP_release\n");
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
	//printk(KERN_INFO "server : device_open(%p)\n", file);

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
	//printk(KERN_INFO "server : device_release(%p,%p)\n", inode, file);

	Device_Open--;

	module_put(THIS_MODULE);
	return 0;
}

static ssize_t device_read(struct file *file, char __user * buffer, size_t length, loff_t * offset)
{
	int bytes_read = 0;

	//printk(KERN_INFO "server : device_read(%p,%p,%d)\n", file, buffer, length);


	if (*Message_Ptr == 0)

	while (length && *Message_Ptr) {

		put_user(*(Message_Ptr++), buffer++);
		length--;
		bytes_read++;
	}

	//printk(KERN_INFO "server : Read %d bytes, %d left\n", bytes_read, length);


	return bytes_read;
}

static ssize_t
device_write(struct file *file, const char __user * buffer, size_t length, loff_t * offset)
{
	int i;

	//printk(KERN_INFO "server : device_write(%p,%s,%d)\n", file, buffer, length);

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


struct tcp_conn_handler_data
{
    struct sockaddr_in *address;
    struct socket *accept_socket;
    int thread_id;
};

struct tcp_conn_handler
{
    struct tcp_conn_handler_data *data[MAXIMUM_CONNECTION];
    struct task_struct *thread[MAXIMUM_CONNECTION];
    int tcp_conn_handler_stopped[MAXIMUM_CONNECTION];
};

struct tcp_conn_handler *tcp_conn_handler;


struct tcp_server_service
{
    int running;
    struct socket *listen_socket;
    struct task_struct *thread;
    struct task_struct *accept_thread;
};

struct tcp_server_service *tcp_server;

char *inet_ntoa(struct in_addr *in)
{
    char *str_ip = NULL;
    u_int32_t int_ip = 0;

    str_ip = kmalloc(16 * sizeof(char), GFP_KERNEL);

    if(!str_ip)
        return NULL;
    else
        memset(str_ip, 0, 16);

    int_ip = in->s_addr;

    sprintf(str_ip, "%d.%d.%d.%d", (int_ip) & 0xFF, (int_ip >> 8) & 0xFF,
                             (int_ip >> 16) & 0xFF, (int_ip >> 16) & 0xFF);

    return str_ip;
}

int tcp_server_send(struct socket *sock, int id, const char *buf,\
                const size_t length, unsigned long flags)
{
    struct msghdr msg;
    struct kvec vec;
    int len, written = 0, left =length;
    mm_segment_t oldmm;

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = flags;
    msg.msg_flags = 0;

    oldmm = get_fs(); set_fs(KERNEL_DS);

repeat_send:
    vec.iov_len = left;
    vec.iov_base = (char *)buf + written;

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
    //printk("len=%d\n",len);
    return written?written:len;
}

int tcp_server_receive(struct socket *sock, int id,struct sockaddr_in *address,\
                unsigned char *buf,int size, unsigned long flags)
{
    struct msghdr msg;
    struct kvec vec;
    int len;
    char *tmp = NULL;

    if(sock==NULL)
    {
        //printk(" receive sock is NULL\n");
        return -1;
    }

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = flags;

    vec.iov_len = size;
    vec.iov_base = buf;

read_again:

    len = kernel_recvmsg(sock, &msg, &vec, size, size, flags);

    if(len == -EAGAIN || len == -ERESTARTSYS)
            goto read_again;

    tmp = inet_ntoa(&(address->sin_addr));

    //printk("client-> %s:%d, says: %s\n", tmp, ntohs(address->sin_port), buf);

    kfree(tmp);
    //len = msg.msg_iter.kvec->iov_len;
    return len;
}

int connection_handler(void *data)
{
    struct tcp_conn_handler_data *conn_data =
            (struct tcp_conn_handler_data *)data;

    struct sockaddr_in *address = conn_data->address;
    struct socket *accept_socket = conn_data->accept_socket;
    int id = conn_data->thread_id;

    int ret = -1;
    int len = MAX_PACKET_SIZE - 1;
    unsigned char in_buf[len+1];
    unsigned char out_buf[len+1];
    //char *tmp;

    DECLARE_WAITQUEUE(recv_wait, current);
    allow_signal(SIGKILL|SIGSTOP);
    /*
    while((ret = tcp_server_receive(accept_socket, id, in_buf, len,\
                                    MSG_DONTWAIT)))
    while(tcp_server_receive(accept_socket, id, in_buf, len,\
                                    MSG_DONTWAIT))
    */
    #if 0
    //printk("server read file\n");
    // ============= open and read file ===============
    struct file *fp;
    struct file *fp1;
    unsigned char buf[MAX_PACKET_SIZE];
    struct kstat file_buf;
    loff_t pos=10;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    //set_fs(get_ds());
    fp=filp_open("README.md", O_RDONLY, 0644);
    fp1=filp_open("README2.md", O_RDWR | O_CREAT, 0644);
    vfs_stat(fp, &file_buf);
    //printk("size=%d\n",file_buf.size);
    if (IS_ERR(fp)){
        printk("error!!!!!!!1\n");
    }

    if (fp!=NULL)
    {
        memset(buf,0,MAX_PACKET_SIZE);
        printk("server: connection_handler to send file\n");

        static int ccount =0;
        ssize_t test=0;
        while (test<0 || ccount <5)
        {
        test = vfs_read(fp,buf, sizeof(buf), &pos);
        ccount+=1;

        printk("count=%d\n",ccount);
        printk("test=%ld\n",test);
        }
        //printk("test=%ld\n",test);
        printk("buf=%s\n",buf);
        pos = fp1->f_pos;
        vfs_write(fp1,buf, test, &pos);
        fp->f_pos = pos;

        filp_close(fp1,NULL);
        filp_close(fp,NULL);
        set_fs(oldfs);

    }
    #endif
    //tcp_server_send(accept_socket, id, buf, strlen(buf), MSG_DONTWAIT);
    while(1)
    {

        add_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);

        while(skb_queue_empty(&accept_socket->sk->sk_receive_queue))
        {
            __set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(HZ);

            if(kthread_should_stop())
            {
                //printk("kthread_stop\n");

                //tcp_conn_handler->thread[id] = NULL;
                tcp_conn_handler->tcp_conn_handler_stopped[id]= 1;

                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&accept_socket->sk->sk_wq->wait,\
                                &recv_wait);
                kfree(tcp_conn_handler->data[id]->address);
                kfree(tcp_conn_handler->data[id]);
                sock_release(tcp_conn_handler->data[id]->accept_socket);

                return 0;
            }

            if(signal_pending(current))
            {
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&accept_socket->sk->sk_wq->wait,\
                                &recv_wait);
                /*
                kfree(tcp_conn_handler->data[id]->address);
                kfree(tcp_conn_handler->data[id]);
                sock_release(tcp_conn_handler->data[id]->accept_socket);
                */
                goto out;
            }
        }
        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);

        //printk("server: receiving message\n");
        memset(in_buf, 0, len+1);
        ret = tcp_server_receive(accept_socket, id, address, in_buf, len, MSG_DONTWAIT);
        if(ret > 0)
        {
            if(memcmp(in_buf, "START", 5) == 0)
            {
                //printk("send?\n");

                tcp_server_send(accept_socket, id, transmit_buff, strlen(transmit_buff), MSG_DONTWAIT);

            }

            if(memcmp(in_buf, "END", 3) == 0)
            {
                //memset(out_buf, 0, len+1);
                //strcat(out_buf, "ADIOSAMIGO");
                //printk("server: sending response: %s\n", out_buf);
                //tcp_server_send(accept_socket, id, out_buf, strlen(out_buf), MSG_DONTWAIT);
                break;
            }
        }

    }

out:

    tcp_conn_handler->tcp_conn_handler_stopped[id]= 1;
    kfree(tcp_conn_handler->data[id]->address);
    kfree(tcp_conn_handler->data[id]);
    sock_release(tcp_conn_handler->data[id]->accept_socket);
    //spin_lock(&tcp_server_lock);
    tcp_conn_handler->thread[id] = NULL;
    //spin_unlock(&tcp_server_lock);
    //return 0;
    do_exit(0);
}

int tcp_server_accept(void)
{
    int accept_err = 0;
    struct socket *socket;
    struct socket *accept_socket = NULL;
    struct inet_connection_sock *isock;
    int id = 0;
    DECLARE_WAITQUEUE(accept_wait, current);

    allow_signal(SIGKILL|SIGSTOP);

    socket = tcp_server->listen_socket;
    while(1)
    {
        struct tcp_conn_handler_data *data = NULL;
        struct sockaddr_in *client = NULL;
        char *tmp;
        int addr_len;

        accept_err = sock_create(socket->sk->sk_family, socket->type, socket->sk->sk_protocol, &accept_socket);

        if(accept_err < 0 || !accept_socket)
        {
            printk("socket create error\n");
            goto err;
        }

        accept_socket->type = socket->type;
        accept_socket->ops  = socket->ops;

        isock = inet_csk(socket->sk);

    //while(1)
    //{
           /*
           struct tcp_conn_handler_data *data = NULL;
           struct sockaddr_in *client = NULL;
           char *tmp;
           int addr_len;
           */

        add_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
        while(reqsk_queue_empty(&isock->icsk_accept_queue))
        {
            __set_current_state(TASK_INTERRUPTIBLE);

            schedule_timeout(HZ);


            if(kthread_should_stop())
            {
                //printk("accept thread stop\n");
                tcp_acceptor_stopped = 1;
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
                sock_release(accept_socket);
                //do_exit(0);
                return 0;
            }

            if(signal_pending(current))
            {
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);
                goto release;
            }

        }
        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&socket->sk->sk_wq->wait, &accept_wait);

        //printk("server: accept connection\n");

        accept_err = socket->ops->accept(socket, accept_socket, O_NONBLOCK);

        if(accept_err < 0)
        {
            //printk("accept error\n");
            goto release;
        }

        client = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
        memset(client, 0, sizeof(struct sockaddr_in));

        addr_len = sizeof(struct sockaddr_in);

        accept_err = accept_socket->ops->getname(accept_socket, (struct sockaddr *)client, &addr_len, 2);

        if(accept_err < 0)
        {
            //printk("getname error\n");
            goto release;
        }


        tmp = inet_ntoa(&(client->sin_addr));

        //printk("server: connection from: %s %d \n", tmp, ntohs(client->sin_port));

        kfree(tmp);

        //printk("server: handle connection\n");


        /*should I protect this against concurrent access?*/
        for(id = 0; id < MAXIMUM_CONNECTION; id++)
        {
            //spin_lock(&tcp_server_lock);
            if(tcp_conn_handler->thread[id] == NULL)
                break;
            //spin_unlock(&tcp_server_lock);
        }

        //printk("gave free id: %d\n", id);

        if(id == MAXIMUM_CONNECTION)
            goto release;

        data = kmalloc(sizeof(struct tcp_conn_handler_data), GFP_KERNEL);
        memset(data, 0, sizeof(struct tcp_conn_handler_data));

        data->address = client;
        data->accept_socket = accept_socket;
        data->thread_id = id;

        tcp_conn_handler->tcp_conn_handler_stopped[id] = 0;
        tcp_conn_handler->data[id] = data;
        tcp_conn_handler->thread[id] =
        kthread_run((void *)connection_handler, (void *)data, "tcp_server");

        if(kthread_should_stop())
        {
            //printk("server: accept thread stop\n");
            tcp_acceptor_stopped = 1;

            return 0;
        }

        if(signal_pending(current))
        {
            break;
        }
    //}
    }

    /*
    kfree(tcp_conn_handler->data[id]->address);
    kfree(tcp_conn_handler->data[id]);
    sock_release(tcp_conn_handler->data[id]->accept_socket);
    */
    tcp_acceptor_stopped = 1;
    //return 0;
    do_exit(0);
release: 
   sock_release(accept_socket);
err:
   tcp_acceptor_stopped = 1;
   //return -1;
   do_exit(0);
}

int tcp_server_listen(void)
{
    int server_err;
    struct socket *conn_socket;
    struct sockaddr_in server;

    DECLARE_WAIT_QUEUE_HEAD(wq);

    //spin_lock(&tcp_server_lock);
    //tcp_server->running = 1;
    allow_signal(SIGKILL|SIGTERM);
    //spin_unlock(&tcp_server_lock);

    server_err = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP,\
                            &tcp_server->listen_socket);
    if(server_err < 0)
    {
        //printk(" socket create error!\n");
        goto err;
    }

    conn_socket = tcp_server->listen_socket;
    tcp_server->listen_socket->sk->sk_reuse = 1;

    //server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT_NUMBER);

    server_err =
    conn_socket->ops->bind(conn_socket, (struct sockaddr*)&server,\
                    sizeof(server));

    if(server_err < 0)
    {
        //printk("bind error!\n");
        goto release;
    }

    //while(1)
    //{
    server_err = conn_socket->ops->listen(conn_socket, 16);

    if(server_err < 0)
    {
        //printk("listen error\n");
        goto release;
    }

    tcp_server->accept_thread = kthread_run((void*)tcp_server_accept, NULL, "tcp_server");

    while(1)
    {
        wait_event_timeout(wq, 0, 3*HZ);

        if(kthread_should_stop())
        {
            //printk("listen thread stop\n");
            /*
            listener_stop = 1;
            sock_release(conn_socket);
            do_exit(0);
            */
            return 0;
        }

        if(signal_pending(current))
                goto release;
    }
    //}

    sock_release(conn_socket);
    listener_stop = 1;
    //return 0;
    do_exit(0);
release:
    sock_release(conn_socket);
err:
    listener_stop = 1;
    //return -1;
    do_exit(0);
}

int tcp_server_start(void)
{
    tcp_server->running = 1;
    tcp_server->thread = kthread_run((void *)tcp_server_listen, NULL,"tcp_server");
    return 0;
}
int readFile(struct file *fp,char *buf,int readlen)
{
    if (fp->f_op && fp->f_op->read)
    {
        return fp->f_op->read(fp,buf,readlen, &fp->f_pos);
    }
    else
    {
        //printk("failed\n");
        return -1;
    }
}
static int __init network_server_init(void)
{
    //printk("server init!!!\n");

    if (strstr(io_mode,"fcntl")!=NULL)
    {
        int ret =0;
        ret = register_chrdev(MAJOR_NUM, "j_ioctl_master", &Fops);
        //printk("ret=%d\n",ret);

        #if 0
        printk("init :server read file\n");
        // ============= open and read file ===============
        struct file *fp;
        ssize_t test=0;
        loff_t pos=0;
        struct file *fp1;
        char buf[MAX_PACKET_SIZE];
        struct kstat file_buf;

        mm_segment_t oldfs;
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        //set_fs(get_ds());
        fp=filp_open("README.md", O_RDONLY, 0644);
        fp1=filp_open("README2.md", O_RDWR | O_CREAT, 0644);
        vfs_stat(fp, &file_buf);
        printk("size=%llu\n",file_buf.size);

        if (fp!=NULL)
        {
            memset(buf,0,MAX_PACKET_SIZE);
            printk("init : server: connection_handler to send file\n");


            static int ccount =0;

            //while (test<0 || ccount <5)
            {
            test = vfs_read(fp,buf, sizeof(buf), &pos);
            printk("pos=%llu\n",pos);
            ccount+=1;
            printk("test=%ld\n",test);
            printk("count=%d\n",ccount);
            }
            //printk("test=%ld\n",test);
            //printk("buf=%s\n",buf);
            pos = fp1->f_pos;
            vfs_write(fp1,buf, test, &pos);
            fp->f_pos = pos;

            memset(&transmit_buff, 0, MAX_PACKET_SIZE);
            strcat(transmit_buff, buf);
            //printk("buffer=%s\n",transmit_buff);
            vfs_fsync(fp1,0);
            filp_close(fp1,NULL);
            filp_close(fp,NULL);

            set_fs(oldfs);

        }
        #endif
    }
    else
    {

        proc_create("j_mmap_master", 0, NULL, &fops);
    }
    tcp_server = kmalloc(sizeof(struct tcp_server_service), GFP_KERNEL);
    memset(tcp_server, 0, sizeof(struct tcp_server_service));

    tcp_conn_handler = kmalloc(sizeof(struct tcp_conn_handler), GFP_KERNEL);
    memset(tcp_conn_handler, 0, sizeof(struct tcp_conn_handler));

    tcp_server_start();
    return 0;
}

static void __exit network_server_exit(void)
{
    int ret;
    int id;

    if(tcp_server->thread == NULL)
        printk("thread is NULL\n");
    else
    {
        for(id = 0; id < MAXIMUM_CONNECTION; id++)
        {
            if(tcp_conn_handler->thread[id] != NULL)
            {

            if(!tcp_conn_handler->tcp_conn_handler_stopped[id])
            {
                ret = kthread_stop(tcp_conn_handler->thread[id]);
                if(!ret)
                    printk("release connect thread: %d\n",id);
                }
            }
        }

        if(!tcp_acceptor_stopped)
        {
            ret = kthread_stop(tcp_server->accept_thread);
            if(!ret)
                printk("accept thread stop\n");
        }

        if(!listener_stop)
        {
            ret = kthread_stop(tcp_server->thread);
            if(!ret)
                printk("listen thrad stop\n");
        }

        if(tcp_server->listen_socket != NULL && !listener_stop)
        {
            sock_release(tcp_server->listen_socket);
            tcp_server->listen_socket = NULL;
        }

        kfree(tcp_conn_handler);
        kfree(tcp_server);
        tcp_server = NULL;
    }

    if (strstr(io_mode,"fcntl")==NULL)
        remove_proc_entry("j_mmap_master", NULL);
    else
        unregister_chrdev(MAJOR_NUM, "j_ioctl_master");
    //printk("server exit \n");
}
module_init(network_server_init)
module_exit(network_server_exit)
