#include "includes.h"

int main(int argc, char **argv)
{	
	int ret = -1; //переменная для проверки ошибок функций
	ret = set_log_settings(argv[0]);
	if(ret != EXIT_SUCCESS)
		return EXIT_FAILURE;
		
	signal(SIGINT, sig_handler); //установка обработчика сигнала для SIGINT

    
	size_t period = 3, num_packets = 0; //периодичность вывода в консоль | кол-во пакетов для захвата
	char *dev; // имя устройства для захвата
	char filter_exp[256] = "tcp port 80 or tcp port 443"; // фильтр захвата

	char errbuf[PCAP_ERRBUF_SIZE]; // буфер для ошибок 
	pcap_t *handle;	// хэндл захвата
    pcap_if_t *device; //все устройства

	struct bpf_program fp; //структура для компиляции фильтра
	bpf_u_int32 mask; // маска
	bpf_u_int32 net; // IP

	ret = arguments_check(argc, argv, num_packets, filter_exp, period);
	if(ret != EXIT_SUCCESS)
		return EXIT_FAILURE;

	//Поиск доступных устройств.
	ret = pcap_findalldevs(&device, errbuf);
	if (ret < 0) 
	{
		cout << "Default device definition error: " << errbuf << endl;
		LOG(FATAL) << "Default device definition error: " << errbuf;
		return EXIT_FAILURE;
	}
	dev = device->name; //По умолчанию первое устройство
	LOG(INFO) << "Default device is set: " << dev;

	//Получаем маску и адрес устройства
	ret = pcap_lookupnet(dev, &net, &mask, errbuf);
	if (ret < 0) 
	{
		cout << "Netmask definition for device " << dev << " error: " << errbuf << endl;
		LOG(FATAL) << "Netmask definition for device " << dev << " error: " << errbuf;
		return EXIT_FAILURE;
	}
	LOG(INFO) << "Netmask for device " << dev << "is set";

	//Создание сессии захвата
	handle = pcap_open_live(dev, 1518, 1, 1000, errbuf);
	if (handle == nullptr) 
	{
		cout << "Device " << dev << " opening error: " << errbuf << endl;
		LOG(FATAL) << "Device " << dev << " opening error: " << errbuf;
		return EXIT_FAILURE;
	}
	LOG(INFO) << "Device " << dev << " opened";
	//Компиляция фильтра
	ret = pcap_compile(handle, &fp, filter_exp, 0, net);
	if (ret < 0) 
	{
		cout << "Filter compile error: " << pcap_geterr(handle) << endl;
		LOG(FATAL) << "Filter compile error: " << pcap_geterr(handle);
		return EXIT_FAILURE;
	}
	LOG(INFO) << "Filter \"" << filter_exp << "\" compiled";
	
	//Установка фильтра
	ret = pcap_setfilter(handle, &fp);
	if (ret < 0) 
	{
		cout << "Filter can't be set: " << pcap_geterr(handle);
		LOG(FATAL) << "Filter can't be set: " << pcap_geterr(handle);
		return EXIT_FAILURE;
	}
	LOG(INFO) << "Filter \"" << filter_exp << "\" is set";
	
	//Получение имени ПК для вывода общей статистики
	ret = gethostname(hostname, 200);
	if(ret < 0)
	{
		cout << "Can't get host name" << endl;
		LOG(FATAL) << "Can't get host name";
		return EXIT_FAILURE;
	}
	info[string(hostname)];
	LOG(INFO) << "Host name is set: " << hostname;

	//Открытие файла для записи информации о полученных пакетах
	fin.open("sniffing_story");
	LOG(INFO) << "File \"sniffing_log\" opened";

	//Создание потока вывода на экран информации о трафике
	cout_stat_thread = thread(cout_stat, period);
	LOG(INFO) << "Thread for output traffic info started";

	//Начало захвата 'num_packets' пакетов
	pcap_loop(handle, num_packets, packet_callback, nullptr);
	stop_thread = true;
	
	//Освобождение ресурсов
	if(!sniffing_buff.empty())
	{
		fin << sniffing_buff;
		sniffing_buff.clear();
	}
	cout_stat_thread.join();
	cout_stat(0); //если программа отработала меньше заданного периода, конечный вывод
	pcap_freecode(&fp);
	pcap_close(handle);
	fin.close();
	LOG(INFO) << "Programm completed successfully";
	return 0;
}
