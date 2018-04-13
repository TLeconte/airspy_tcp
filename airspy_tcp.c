/*
 * Copyright (C) 2012 by Steve Markgraf <steve@steve-m.de>
 * Copyright (C) 2012-2013 by Hoernchen <la@tfc-server.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Airspy port :
 * Copyright (C) 2018 by Thierry Leconte http://www.github.com/TLeconte
 *
 */

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <pthread.h>

#include <libairspy/airspy.h>

#define SOCKADDR struct sockaddr
#define SOCKET int
#define SOCKET_ERROR -1

static SOCKET s;

static pthread_t tcp_worker_thread;
static pthread_t command_thread;
static pthread_cond_t exit_cond;
static pthread_mutex_t exit_cond_lock;

static pthread_mutex_t ll_mutex;
static pthread_cond_t cond;

struct llist {
	char *data;
	size_t len;
	struct llist *next;
};

typedef struct { /* structure size must be multiple of 2 bytes */
	char magic[4];
	uint32_t tuner_type;
	uint32_t tuner_gain_count;
} dongle_info_t;

static struct airspy_device* dev = NULL;
static uint32_t fscount,*supported_samplerates;
static int verbose=0;
static int ppm_error=0;
static int dshift=1;

static int enable_biastee = 0;
static int global_numq = 0;

static struct llist *ls_buffer = NULL;
static struct llist *le_buffer = NULL;
static int llbuf_num = 64;

static volatile int do_exit = 0;

void usage(void)
{
	printf("airspy_tcp, a rtl-tcp compatible, I/Q server for airspy SDR\n\n"
		"Usage:\t[-a listen address]\n"
		"\t[-p listen port (default: 1234)]\n"
		"\t[-f frequency to tune to [Hz]]\n"
		"\t[-g gain (default: 0 for auto)]\n"
		"\t[-s samplerate in Hz ]\n"
		"\t[-n max number of linked list buffer to keep ]\n"
		"\t[-T enable bias-T ]\n"
		"\t[-P ppm_error (default: 0) ]\n"
		"\t[-D g digital shift (default : 1) ]\n"
		"\t[-v Verbose ]\n");
	exit(1);
}

static void sighandler(int signum)
{
	fprintf(stderr, "Signal caught, exiting!\n");
        airspy_stop_rx(dev);
	do_exit = 1;
}

static int rx_callback(airspy_transfer_t* transfer)
{
	short *buf;
	int len;


	len=2*transfer->sample_count;
	buf=(short *)transfer->samples;

	if(!do_exit) {
		int i;
		char *data;
		struct llist *rpt;

		rpt = (struct llist*)malloc(sizeof(struct llist));
		rpt->data = malloc(len);
		rpt->len = len;
		rpt->next = NULL;

		data=rpt->data;
		for(i=0;i<len;i++,buf++,data++) {
			short v=*buf<<dshift;
			short o;

			 /* stupid added offset, because osmosdr client code */
			 /* try to compensate rtl dongle offset */
			 o=(v-154)>>8;

			/* round to 8bits half up to even */
			if(v&0x80) {
			 if(v&0x7f) {o++;} else { if(v&0x100) o++;}
			}

			*data=(unsigned char)((o&0xff)+128);
		}

		pthread_mutex_lock(&ll_mutex);

		  if (ls_buffer == NULL) {
			ls_buffer = le_buffer = rpt;
		  } else {
			le_buffer->next=rpt;
			le_buffer=rpt;
		  }
		  global_numq++;

		if(global_numq>llbuf_num) {
			struct llist *curelem;
			curelem=ls_buffer;
			ls_buffer=ls_buffer->next;
			if(ls_buffer==NULL) le_buffer==NULL;
			global_numq--;
			free(curelem->data);
			free(curelem);
		}

		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&ll_mutex);
	}
	return 0;
}

static void *tcp_worker(void *arg)
{
	struct llist *curelem;
	int bytesleft,bytessent, index;

	while(1) {
		if(do_exit)
			pthread_exit(0);

		pthread_mutex_lock(&ll_mutex);
		while(ls_buffer==NULL)
			pthread_cond_wait(&cond, &ll_mutex);

		curelem = ls_buffer;
		ls_buffer=ls_buffer->next;
		global_numq--;
		pthread_mutex_unlock(&ll_mutex);

		bytesleft = curelem->len;
		index = 0;
		while(bytesleft > 0) {
			bytessent = send(s,  &curelem->data[index], bytesleft, 0);
			bytesleft -= bytessent;
			index += bytessent;
			if(bytessent == SOCKET_ERROR || do_exit) {
					printf("worker socket bye\n");
					sighandler(0);
					pthread_exit(NULL);
			}
		}
		free(curelem->data);
		free(curelem);
	}
}

struct command{
	unsigned char cmd;
	unsigned int param;
}__attribute__((packed));


static int set_agc(uint8_t value)
{
	int r;

	r=airspy_set_lna_agc(dev, value);
        if( r != AIRSPY_SUCCESS ) return r;


	r=airspy_set_mixer_agc(dev, value);
        return r;
}


static int set_samplerate(uint32_t fs)
{
	int r,i;

        for(i=0;i<fscount;i++)
      		if(supported_samplerates[i]==fs) break;
	if(i>=fscount) {
		printf("sample rate %d not supported\n",fs);
		return AIRSPY_ERROR_INVALID_PARAM;
	}

       	r=airspy_set_samplerate(dev, i);
	return r;
}

static int set_freq(uint32_t f)
{
	int r;

       	r=airspy_set_freq(dev, (uint32_t)((float)f*(1.0+(float)ppm_error/1e6)));
	return r;
}

static void *command_worker(void *arg)
{
	int left, received = 0;
	fd_set readfds;
	struct command cmd={0, 0};
	struct timeval tv= {1, 0};
	int r = 0;

	while(1) {
		left=sizeof(cmd);
		while(left >0) {
			FD_ZERO(&readfds);
			FD_SET(s, &readfds);
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			r = select(s+1, &readfds, NULL, NULL, &tv);
			if(r) {
				received = recv(s, (char*)&cmd+(sizeof(cmd)-left), left, 0);
				left -= received;
			}
			if(received == SOCKET_ERROR || do_exit) {
				printf("comm recv bye\n");
				sighandler(0);
				pthread_exit(NULL);
			}
		}
		switch(cmd.cmd) {
		case 0x01:
			if(verbose) printf("set freq %d\n", ntohl(cmd.param));
			set_freq(ntohl(cmd.param));
			break;
		case 0x02:
			if(verbose) printf("set sample rate : %d\n", ntohl(cmd.param));
			set_samplerate(ntohl(cmd.param));
			break;
		case 0x03:
			if(verbose) printf("set gain mode %d : not implemented \n", ntohl(cmd.param));
		case 0x04:
			if(verbose) printf("set gain : %d\n", ntohl(cmd.param));
			airspy_set_linearity_gain(dev,(ntohl(cmd.param)+240)/35);
			break;
		case 0x05:
			if(verbose) printf("set freq correction %d\n",ntohl(cmd.param));
			ppm_error=ntohl(cmd.param);
			break;
		case 0x06:
			if(verbose) printf("set if stage gain %d : not implemented\n",ntohl(cmd.param));
			break;
		case 0x07:
			if(verbose) printf("set test mode %d: not impmemented\n",ntohl(cmd.param));
			break;
		case 0x08:
			set_agc(ntohl(cmd.param));
			break;
		case 0x09:
			if(verbose) printf("set direct sampling %d: not implemented\n",ntohl(cmd.param));
			break;
		case 0x0a:
			if (verbose) printf("set offset tuning %d : not impemented\n",ntohl(cmd.param));
			break;
		case 0x0b:
			if(verbose) printf("set rtl xtal %d : not implemented\n",ntohl(cmd.param));
			break;
		case 0x0c:
			if(verbose) printf("set tuner xtal %d : not implemented\n",ntohl(cmd.param));
			break;
		case 0x0d:
			if(verbose) printf("set tuner gain by index %d \n", ntohl(cmd.param));
			airspy_set_linearity_gain(dev,ntohl(cmd.param));
			break;
		case 0x0e:
			if(verbose) printf("set bias tee %d\n", ntohl(cmd.param));
			airspy_set_rf_bias(dev, (int)ntohl(cmd.param));
			break;
		default:
			break;
		}
		cmd.cmd = 0xff;
	}
}

int main(int argc, char **argv)
{
	int r, opt;
	char* addr = "127.0.0.1";
	int port = 1234;
	uint32_t frequency = 100000000,samp_rate = 0;
	struct sockaddr_in local, remote;
	int gain = 0;
	struct llist *curelem,*prev;
	pthread_attr_t attr;
	void *status;
	struct timeval tv = {1,0};
	struct linger ling = {1,0};
	SOCKET listensocket;
	socklen_t rlen;
	fd_set readfds;
	dongle_info_t dongle_info;
	struct sigaction sigact, sigign;

	while ((opt = getopt(argc, argv, "a:p:f:g:s:b:n:d:P:TD:v")) != -1) {
		switch (opt) {
		case 'f':
			frequency = (uint32_t)atoi(optarg);
			break;
		case 'g':
			gain = (int)(atof(optarg) * 10); /* tenths of a dB */
			break;
		case 's':
			samp_rate = (uint32_t)atoi(optarg);
			break;
		case 'a':
			addr = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			llbuf_num = atoi(optarg);
			break;
		case 'T':
			enable_biastee = 1;
			break;
                case 'P':
                        ppm_error = atoi(optarg);
                        break;
                case 'D':
                        dshift = atoi(optarg);
                        break;
		case 'v':
			verbose = 1;
			break;
		case 'b':
			break;

		default:
			usage();
			break;
		}
	}

	if (argc < optind)
		usage();

        r = airspy_open(&dev);
        if( r != AIRSPY_SUCCESS ) {
                fprintf(stderr,"airspy_open() failed: %s (%d)\n", airspy_error_name(r), r);
                airspy_exit();
                return -1;
        }

        r = airspy_set_sample_type(dev, AIRSPY_SAMPLE_INT16_IQ);
        if( r != AIRSPY_SUCCESS ) {
                fprintf(stderr,"airspy_set_sample_type() failed: %s (%d)\n", airspy_error_name(r), r);
                airspy_close(dev);
                airspy_exit();
                return -1;
        }

	airspy_set_packing(dev, 1);

        r=airspy_get_samplerates(dev, &fscount, 0);
        if( r != AIRSPY_SUCCESS ) {
                fprintf(stderr,"airspy_get_sample_rate() failed: %s (%d)\n", airspy_error_name(r), r);
                airspy_close(dev);
                airspy_exit();
                return -1;
	}
        supported_samplerates = (uint32_t *) malloc(fscount * sizeof(uint32_t));
        r=airspy_get_samplerates(dev, supported_samplerates, fscount);
        if( r != AIRSPY_SUCCESS ) {
                fprintf(stderr,"airspy_get_sample_rate() failed: %s (%d)\n", airspy_error_name(r), r);
                airspy_close(dev);
                airspy_exit();
                return -1;
	}

	if(samp_rate) {
        	r = set_samplerate(samp_rate);
        	if( r != AIRSPY_SUCCESS ) {
                	fprintf(stderr,"set_samplerate() failed: %s (%d)\n", airspy_error_name(r), r);
                	airspy_close(dev);
                	airspy_exit();
                	return -1;
        	}
	} else {
       		r=airspy_set_samplerate(dev, fscount-1);
        	if( r != AIRSPY_SUCCESS ) {
                	fprintf(stderr,"airspy_set_samplerate() failed: %s (%d)\n", airspy_error_name(r), r);
                	airspy_close(dev);
                	airspy_exit();
                	return -1;
        	}
	}

	/* Set the frequency */
        r = set_freq(frequency);
        if( r != AIRSPY_SUCCESS ) {
                fprintf(stderr,"airspy_set_freq() failed: %s (%d)\n", airspy_error_name(r), r);
                airspy_close(dev);
                airspy_exit();
                return -1;
        }

        if (0 == gain) {
		 /* Enable automatic gain */
		r=set_agc(1);
       		if( r != AIRSPY_SUCCESS ) {
               		fprintf(stderr,"airspy_set agc failed: %s (%d)\n", airspy_error_name(r), r);
       		}
	} else {
        	r = airspy_set_linearity_gain(dev,(gain+240)/35);
       		if( r != AIRSPY_SUCCESS ) {
               		fprintf(stderr,"set gains failed: %s (%d)\n", airspy_error_name(r), r);
               		airspy_close(dev);
               		airspy_exit();
               		return -1;
       		}
		if(verbose) fprintf(stderr, "Tuner gain set to %f dB.\n", gain/10.0);
	}

        r = airspy_set_rf_bias(dev, enable_biastee);
        if( r != AIRSPY_SUCCESS ) {
                fprintf(stderr,"airspy_set_rf_bias() failed: %s (%d)\n", airspy_error_name(r), r);
                airspy_close(dev);
                airspy_exit();
                return -1;
        }

	sigact.sa_handler = sighandler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigign.sa_handler = SIG_IGN;
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGQUIT, &sigact, NULL);
	sigaction(SIGPIPE, &sigign, NULL);

	pthread_mutex_init(&exit_cond_lock, NULL);
	pthread_mutex_init(&ll_mutex, NULL);
	pthread_mutex_init(&exit_cond_lock, NULL);
	pthread_cond_init(&cond, NULL);
	pthread_cond_init(&exit_cond, NULL);

	memset(&local,0,sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = inet_addr(addr);

	listensocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	r = 1;
	setsockopt(listensocket, SOL_SOCKET, SO_REUSEADDR, (char *)&r, sizeof(int));
	setsockopt(listensocket, SOL_SOCKET, SO_LINGER, (char *)&ling, sizeof(ling));
	bind(listensocket,(struct sockaddr *)&local,sizeof(local));

	r = fcntl(listensocket, F_GETFL, 0);
	r = fcntl(listensocket, F_SETFL, r | O_NONBLOCK);

	while(1) {
		printf("listening...\n");
		printf("Use the device argument 'rtl_tcp=%s:%d' in OsmoSDR "
		       "(gr-osmosdr) source\n"
		       "to receive samples in GRC and control "
		       "parameters (frequency, gain, ...).\n",
		       addr, port);
		listen(listensocket,1);

		while(1) {
			FD_ZERO(&readfds);
			FD_SET(listensocket, &readfds);
			tv.tv_sec = 1;
			tv.tv_usec = 0;
			r = select(listensocket+1, &readfds, NULL, NULL, &tv);
			if(do_exit) {
				goto out;
			} else if(r) {
				rlen = sizeof(remote);
				s = accept(listensocket,(struct sockaddr *)&remote, &rlen);
				break;
			}
		}

		setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&ling, sizeof(ling));
		r=5;setsockopt(s, SOL_SOCKET, SO_PRIORITY, (char *)&r, sizeof(int));

		printf("client accepted!\n");

		memset(&dongle_info, 0, sizeof(dongle_info));
		memcpy(&dongle_info.magic, "RTL0", 4);

		dongle_info.tuner_type = htonl(5);
		dongle_info.tuner_gain_count = htonl(22);

		r = send(s, (const char *)&dongle_info, sizeof(dongle_info), 0);
		if (sizeof(dongle_info) != r) {
			printf("failed to send dongle information\n");
			break;
		}

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
		r = pthread_create(&tcp_worker_thread, &attr, tcp_worker, NULL);
		r = pthread_create(&command_thread, &attr, command_worker, NULL);
		pthread_attr_destroy(&attr);

		r = airspy_start_rx(dev, rx_callback, NULL);
		if( r != AIRSPY_SUCCESS ) {
        		fprintf(stderr,"airspy_start_rx() failed: %s (%d)\n", airspy_error_name(r), r);
			break;
		}

		pthread_join(tcp_worker_thread, &status);
		pthread_join(command_thread, &status);

		close(s);

		fprintf(stderr,"close\n");

                r = airspy_stop_rx(dev);
                if( r != AIRSPY_SUCCESS ) {
                        fprintf(stderr,"airspy_stop_rx() failed: %s (%d)\n", airspy_error_name(r), r);
			break;
                }

		curelem = ls_buffer;
		while(curelem != 0) {
			prev = curelem;
			curelem = curelem->next;
			free(prev->data);
			free(prev);
		}
		ls_buffer=le_buffer=NULL;
		global_numq = 0;

		do_exit = 0;
	}

out:
	airspy_close(dev);
	airspy_exit();
	close(listensocket);
	close(s);
	printf("bye!\n");
	return r >= 0 ? r : -r;
}
