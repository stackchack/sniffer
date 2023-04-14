#include <iostream>
#include <fstream>
#include <chrono>
#include <pcap/pcap.h>
#include <string.h>
#include <signal.h>
#include <map>
#include <thread>

#include <glog/logging.h>
#include <glog/raw_logging.h>

using namespace std;

//Структура для парсинга пакета (украдено из статьи https://www.tcpdump.org/pcap.html)
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

//Структура для хранения информации о трафике
struct traffic_info
{
	long long int b_in = 0, packets_in = 0;
	long long int b_out = 0, packets_out = 0;
};


inline char hostname[200]; //Имя ПК

inline  string sniffing_buff; //буфер для записи в файл

inline  ofstream fin; //файловый поток вывода информации в файл

inline  thread cout_stat_thread; //Поток вывода данных на экран

inline  bool stop_thread = false; //Для корректного завершения потока

//Статистика по каждому адресу
inline map<string, traffic_info> info;

//Получение имени по адресу, если возможно
int get_dns_name(char* dns_name, in_addr ip_addr);

//callback функция для обработки пакетов
void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

//Вывод справки о программе
void print_help();

//Вывод на экран
void cout_stat(size_t period);

//Обработчик сигнала SIGINT
void sig_handler(int signal);

//Настройка параметров логгирования
int set_log_settings(char* argv_0);

//Проверка аргументов командной строки
int arguments_check(int argc, char** argv, size_t& num_packets, char* filter_exp, size_t& period);
