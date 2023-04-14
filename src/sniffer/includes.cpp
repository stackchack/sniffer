#include "includes.h"



int get_dns_name(char* dns_name, in_addr ip_addr)
{
	if(dns_name == nullptr)
	{
		LOG(ERROR) << "nullptr was recieved";
		return EXIT_FAILURE;
	}
	int ret = 0;
	struct sockaddr_in sock;
    memset(&sock, 0, sizeof(sock));
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = ip_addr.s_addr;
    sock.sin_port = 0;
    ret = getnameinfo( (struct sockaddr *)&sock, sizeof(sock), dns_name, NI_MAXHOST, NULL, 0, 0);
	if(ret != 0)
	{	
		LOG(WARNING) << "Can't get dns name for: " << inet_ntoa(ip_addr);
		return EXIT_FAILURE;
	}
	LOG(INFO) << "Dns name for: " << inet_ntoa(ip_addr) << " : " << dns_name;
	return EXIT_SUCCESS;
}

void packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	LOG(INFO) << "Got packet: packet size: " << header->len;
	
	//время получения пакета
	auto now = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(now); 

	static int count = 0; count++; //количество полученных пакетов            
	int ret = 0; // проверка возвращаемых значений
	string fout_buff, s_name_src, s_name_dst; //буфер записи в файл, имя источника и имя отправителя в string формате

	const struct sniff_ip *ip;              
	char name_src[NI_MAXHOST] = ""; // Имя отправителя
	char name_dst[NI_MAXHOST] = ""; //Имя получателя

	//Смещение
	ip = (struct sniff_ip*)(packet + 14);
	
	//Получаем имя источника и получателя
	ret = get_dns_name(name_src, ip->ip_src);
	if(ret != EXIT_SUCCESS)
		s_name_src = string(inet_ntoa(ip->ip_src));
	else
		s_name_src = string(name_src);

	ret = get_dns_name(name_dst, ip->ip_dst);
	if(ret != EXIT_SUCCESS)
		s_name_dst = string(inet_ntoa(ip->ip_dst));
	else
		s_name_dst = string(name_dst);

	//Добавляем данные в буфер вывода в файл
	fout_buff = s_name_src + "(" + string(inet_ntoa(ip->ip_src)) + ") -> " +
		s_name_dst + "(" + string(inet_ntoa(ip->ip_dst)) + ") | " + to_string(header->len) +
		 " Bytes | " +	string(ctime(&end_time));

	//Обновляем/добавляем информацию по источнику/отправителю
	if(info.find(s_name_src) == info.end())
	{
		info[s_name_src];
		LOG(INFO) << "Added new addres: " << inet_ntoa(ip->ip_src);
	}
	if(info.find(s_name_dst) == info.end())
	{
		info[s_name_dst];
		LOG(INFO) << "Added new addres: " << inet_ntoa(ip->ip_dst);
	}
	if(s_name_src == string(hostname))
	{
		info[s_name_src].b_out += header->len;
		info[s_name_src].packets_out += 1;
		info[s_name_dst].b_out += header->len;
		info[s_name_dst].packets_out += 1;
	}
	else
	{
		info[s_name_src].b_in += header->len;
		info[s_name_src].packets_in += 1;
		info[s_name_dst].b_in += header->len;
		info[s_name_dst].packets_in += 1;
	}

	sniffing_buff += fout_buff;
	if(count % 20 == 0) //Каждые 20 пакетов запись в файл
	{
			fin << sniffing_buff;
			sniffing_buff.clear(); //Очищаем буфер
			LOG(INFO) << "Sniffing buffer is clear";
	}
	
	
return;
}

void print_help()
{
	cout << 
	"Run program without arguments means using the default settings: " << endl <<
	"filter expression: \"tcp port 80 or 443\"" << endl <<
	"packets capturing until the end of the program" << endl << endl <<
	"You can specify a filter or number packets for capturing by giving it as an argument:" << endl <<
	"          -c N - for capturing N packets (0 - default)" << endl <<
	"          -f \"filter expression\"" << endl;
}

void cout_stat(size_t period)
{
	if(period > 10)
		period = 3;
	do
	{	system("clear");
		for(const auto& elem : info)
			cout << ">" << elem.first << " | " << elem.second.b_in << " Byte IN (" << elem.second.packets_in << " packets) | " <<
			elem.second.b_out << " Byte OUT (" << elem.second.packets_out << " packets)" << endl;
			sleep(1);
	}
	while(!stop_thread);
}

void sig_handler(int signal)
{
	if(!sniffing_buff.empty())
	{
		fin << sniffing_buff;
		sniffing_buff.clear();
	}
	stop_thread = true;
	cout_stat_thread.join();
	cout_stat(0); //если программа отработала меньше заданного периода, конечный вывод
	fin.close();
	LOG(INFO) << "Program completed successfully";
	exit(EXIT_SUCCESS);

}

int set_log_settings(char* argv_0)
{
	if(argv_0 == nullptr)
		return EXIT_FAILURE;
	int ret = 0;
	google::InitGoogleLogging(argv_0);
	fLS::FLAGS_log_dir = "./glogs_"; //устанавливаем папку для записи логов
	FLAGS_logtostderr = false;
	ret = system("mkdir glogs_");//создаем директорию для записи логов (если уже есть - некритичиская ошибка)
	if(ret == 256) 
		LOG(WARNING) << "Directory '_glogs_' can't be created: already exists";
	else if(ret == 0)
		LOG(INFO) << "Directory '_glogs_' created";
	
    return EXIT_SUCCESS;
}

int arguments_check(int argc, char** argv, size_t& num_packets, char* filter_exp, size_t& period)
{
	if(filter_exp == nullptr || argv == nullptr)
	{
		cout << "nullptr is recieved" << endl;
		LOG(ERROR) << "Programm terminated: nullptr is recieved: ";
		return EXIT_FAILURE;
	}
	int check = 0;
	if(argc > 7)
	{
		cout << "Too much arguments." << endl << "Use '-h' as an launch argument to see tip." << endl;
		LOG(ERROR) << "Programm terminated: too much arcgument recieved: " << argc;
		return EXIT_FAILURE;
	}
	for(size_t i = 0; i < argc; ++i)
	{	
		if(string(argv[i]) == "-h")
		{
			print_help();
			return EXIT_SUCCESS;
		}
		else if(string(argv[i]) == "-f")
		{
			filter_exp = argv[i+1];
			LOG(INFO) << "Filter expreission is set: " << filter_exp;
		}
		else if(string(argv[i]) == "-c")
		{	
			try
			{	check = stoi(string(argv[i + 1]));
				if(check < 0)
				{
					cout << "Invalid number: " << argv[i+1] << endl;
					LOG(FATAL) << "Number packets for capturing can't be set: invalid value: " << argv[i+1];
					return EXIT_FAILURE;
				}
				num_packets = check;
				LOG(INFO) << "Number packets is set: " << num_packets;
			}
			catch(const std::exception& e)
			{
				cout << "Invalid number: " << argv[i+1] << endl;
				LOG(FATAL) << "Number packets for capturing can't be set: invalid value: " << argv[i+1];
				return EXIT_FAILURE;
			}
		}
		else if(string(argv[i]) == "-t")
		{
			try
			{
				check = stoi(string(argv[i + 1]));
				if(check < 0)
				{
					cout << "Invalid number: " << argv[i+1] << endl;
					LOG(FATAL) << "Timeout for output can't be set: invalid value: " << argv[i+1];
					return EXIT_FAILURE;
				}
				period = check;
				LOG(INFO) << "Timeout for output is set: " << period;
			}
			catch(const std::exception& e)
			{
				cout << "Invalid number: " << argv[i+1] << endl;
				LOG(FATAL) << "Timeout for output can't be set: invalid value: " << argv[i+1];
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}


