#include<stdio.h>
#include <WinSock2.h>
#include <windows.h>
#include<time.h>
#include<thread>
#include"random.h"
#include"AES.h"
using namespace std;
#define max_threads 10
#pragma comment(lib,"ws2_32.lib") //Winsock Library

string CIP = "127.0.0.2";
string SIP = "127.0.0.1";
int SPort = 2222;
int CPort = 3333;
SOCKADDR_IN servaddr, clieaddr;
SOCKET s;
SOCKET cl;
sockaddr_in client_addr;

int shake_state = 0;
string ID_A = "moon", ID_B = "sun";
bigInt N1, N2;//�����
bigInt Key;
string n_astr("101407628385108512925543677817200169344315054987033955320928719787018970982119759558416101819705107356503132441709662510959075194536940982001001853936941528772339111711633210419437875155697629171356440179152472454681528060205111932316734300230180361045256856077963659361244405727024274873659438824808932559837");
string e_astr("67605085590072341950362451878133446229543369991355970213952479858012647321413173038944067879803404904335421627806441673972716796357960654667334569291294339086869511624942965644888917234847462412332496550667861934366478347209409934664169822352669355229507405669269234419537144980672410743487955205837182097771");
bigInt n_A(n_astr), e_A(e_astr);//�Է��Ĺ�Կ
string n_bstr("77195310450224681443701893280619391413301600979699348131159112344340188591003633601945314755687418430548046225959369455023014162580305823887079348500824458424309499826749021637802441598901295989466525304697081741335985344074342189900590837317256395491721089528941320109592538404471271067312411688184475868507");
string e_bstr("61756248360179745154961514624495513130641280783759478504927289875472150872802906881556251804549934744438436980767495564018411330064244659109663478800659552353300559002711875906687152089348850864638154247293963504151360382230647576693207007024044024700221519798337578323478606375788824679599087491273293306765");
string d_bstr("5");
bigInt n_B(n_bstr), e_B(e_bstr), d_B(d_bstr);//�����Ĺ�Կ��˽Կ
bool isRecv = 0, isSend = 0;
DWORD  recvThread(SOCKET cli);
DWORD  sendThread(SOCKET cli);
void decrypt_rsa(bigInt* Cipher, bigInt * mes, bigInt n, bigInt e);
//void encrypt_rsa(char* mes, char* Cipher, bigInt n, bigInt d);
void encrypt_rsa(bigInt* mes, bigInt* Cipher, bigInt n, bigInt d);
string welcome = "\n"
" _____   _____                             ______  _____ \n"
"|  __ \\ / ____|  /\\       ___        /\\   |  ____|/ ____|\n"
"| |__) | (___   /  \\     ( _ )      /  \\  | |__  | (___  \n"
"|  _  / \\___ \\ / /\\ \\    / _ \\/\\   / /\\ \\ |  __|  \\___ \\ \n"
"| | \\ \\ ____) / ____ \\  | (_>  <  / ____ \\| |____ ____) |\n"
"|_|  \\_\\_____/_/    \\_\\  \\___/\\/ /_/    \\_\\______|_____/ \n"
"                                                           \n"
"                                                           \n";

int main(int argc, char* argv[])
{
	cout << "��ӭʹ��RSA & AES���ܴ���Ի�ϵͳ" << endl;
	cout << welcome;
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSADATA��ʼ��ʧ�ܣ������� : %d", WSAGetLastError());
		return 1;
	}
	printf("WSADATA��ʼ�����...\n");

	//Create a socket
	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		printf("Socket����ʧ�ܣ������룺%d", WSAGetLastError());
		return 1;
	}
	printf("Socket�����ɹ�...\n");


	//servaddr.sin_addr.s_addr = INADDR_ANY;//����������������
	servaddr.sin_addr.s_addr = inet_addr(SIP.c_str());//inet_addr use for convert the ip address to a long format, inet_ntoa is opposite
	servaddr.sin_family = AF_INET;//IPv4
	servaddr.sin_port = htons(SPort);

	//Bind
	if (bind(s, (struct sockaddr*)&servaddr, sizeof(servaddr)) == SOCKET_ERROR)
	{
		printf("Bind��ʧ�� : %d", WSAGetLastError());
		return 1;
	}
	printf("Bind�󶨱���ip�ɹ�\n");

	listen(s, max_threads);

	printf("�ȴ��ͻ�������...\n");


	while (1)
	{
		int c;
		struct sockaddr_in client;
		c = sizeof(struct sockaddr_in);
		if ((cl=(accept(s, (struct sockaddr*)&client, &c))) != INVALID_SOCKET) 
		{

			printf("��%s���ӳɹ�\n", inet_ntoa(client.sin_addr));		
			printf("�Ƿ�Ҫ��%s���ͻỰ����1.�� 2.��\n",ID_A.c_str());
			int flag_ask;
			cin >> flag_ask;
			if (flag_ask == 1) {
				isRecv = 0;
				isSend = 1;
			}
			else {
				isRecv = 1;
				isSend = 0;
			}
			thread re(recvThread,cl);
			thread se(sendThread,cl);
			se.detach();
			re.detach();		

		}
		else {
			printf("accept failed with error code : %d", WSAGetLastError());
			return 1;
		}
	}
	closesocket(s);
	return 0;
}


DWORD  recvThread(SOCKET cli)
{
	while (1) {
		if (shake_state == 5 && isRecv) {//AES���ܣ������ʼ����IV
			char recvCipher[1024] = { '\0' };
			int lenCipher = 1023;

			if (recv(cli, recvCipher, 1024, 0) != SOCKET_ERROR);			
			char mes[1024] = { '\0' }, mes_encrypt[1024] = { '\0' };
			memcpy_s(mes_encrypt, 1024, recvCipher, sizeof(recvCipher));
			char keytemp[16] = { '\0' };
			memcpy_s(keytemp, 16, bigInt2string(Key).c_str(), 16);
			decrypt_aes(keytemp, mes, mes_encrypt,ECB);
			memset(mes + lenCipher, 0x0, 1024 - lenCipher - 1);
			memcpy_s(IV, 1024, mes, 1024);
			shake_state = 6;
			cout << "���յ�CBCģʽ��ʼ����IV" << endl;
		}
		else if (shake_state == 6) {//AES���ܣ������ʼ����IV
			char recvCipher[1024] = { '\0' };

			if (recv(cli, recvCipher, 1024, 0) != SOCKET_ERROR);
			char mes[1024] = { '\0' }, mes_encrypt[1024] = { '\0' };
			memcpy_s(mes_encrypt, 1024, recvCipher, sizeof(recvCipher));
			char keytemp[16] = { '\0' };
			memcpy_s(keytemp, 16, bigInt2string(Key).c_str(), 16);
			decrypt_aes(keytemp, mes, mes_encrypt, CBC);
			if (strcmp(mes, "exit") == 0) {
				printf("�Է�ֹͣ���У���������Э���˳�\n");
				closesocket(cli);
				return 0;
			}
			else {
				cout << ID_A << ":" << string(mes) << endl;
			}			
		}

		else {
			if ((isRecv && !isSend)) {
				char recvCipher[1024] = { '\0' };
				int lenCipher = 1023;
				if (recv(cli, recvCipher, 1024, 0) != SOCKET_ERROR) {
					for (int i = 0; i < 1024; i++) {
						if (!(recvCipher[i] <= '9' && recvCipher[i] >= '0')) {//������ܶ�����Ϣ
							lenCipher = i;
							break;
						}
					}
					memset(recvCipher + lenCipher, 0x0, 1024 - lenCipher - 1);

					bigInt mes_decrypt;
					string strCipher(recvCipher);
					bigInt biCipher(strCipher);
					decrypt_rsa(&biCipher, &mes_decrypt, n_B, d_B);
					if (shake_state == 13 && (isRecv || !isSend)) {//�շ���stage4
						printf("�յ����󷽷��͵�Key����������AES���ܻỰ\n");
						shake_state = 5;
						bigInt k_mes;
						decrypt_rsa(&mes_decrypt, &k_mes, n_A, e_A);
						Key = k_mes;
					}
					else {
						if (shake_state == 0 && (isRecv || !isSend)) {//�շ���stage1
							printf("�յ����󷽷��͵�N1��ID����������stage2\n");
							isRecv = 1;
							shake_state = 11;
							string temp = bigInt2string(mes_decrypt);
							//string temp = bigInt2string(biCipher);
							string N1str = "", IDstr = ""; int lenN1=1023;
							for (int i = 0; i < temp.size() - 2; i++) {
								if (!(temp[i] == '|' && temp[i + 1] == '|' && temp[i + 2] == '|')) {
									N1str += temp[i];
								}
								else {
									lenN1 = i;
									break;
								}
							}
							for (int i = lenN1 + 3; i < temp.size(); i++) {
								IDstr += temp[i];
							}
							N1 = string2bigInt(N1str);
							printf("�Է�IDΪ��%s\n", IDstr.c_str());
							
							isSend = 0;
							isRecv = 1;
							bigInt sN2;
							sN2 = random(64, sN2);
							N2 = sN2;
							bigInt Cipher;
							string temp1_str = bigInt2string(sN2) + "|||" + bigInt2string(sN2);
							bigInt plain = string2bigInt(temp1_str);
							encrypt_rsa(&plain, &Cipher, n_A, e_A);//������bigInt
							char sendCipher[1024];
							memcpy_s(sendCipher, 1024, Cipher.getnum().c_str(), Cipher.getnum().size());
							send(cli, sendCipher, 1024, 0);
							printf("stage2�������󷽻ظ�N1��N2\n");//�շ���stage2
							shake_state = 2;
							continue;
						}
						else if (shake_state == 2 && (isRecv || !isSend)) {//�շ���stage3
							printf("�յ����󷽻ظ���N2���ȶ���ȷ����������stage4\n");
							isRecv = 1;
							shake_state = 13;
							bigInt N2cmp = mes_decrypt;
							if (!(N2 == N2cmp)) {
								printf("stage 3,N2��ƥ��");
								return 0;
							}
							continue;
						}
					}

				}
			}
		}				
	}
	return 0;
}

DWORD  sendThread(SOCKET cli)
{

	while (1)
	{			
		if (isSend&&shake_state==0) {//������stage1
			isSend = 1; isRecv = 0;
			bigInt sN1;
			sN1 = random(64, sN1);
			N1 = sN1;
			bigInt Cipher;
			string temp1_str = bigInt2string(sN1);
			temp1_str += "|||";
			temp1_str += ID_B;//ID_str���Լ���Id����
			bigInt plain = string2bigInt(temp1_str), enc;
			encrypt_rsa(&plain, &Cipher, n_A, e_A);//������bigInt
			char sendCipher[1024];
			memcpy_s(sendCipher, 1024, Cipher.getnum().c_str(), Cipher.getnum().size());
			if (send(cli, sendCipher, 1024, 0) >= 0) {
				printf("��Է������У��ѷ���N1��ID����������stage2\n");
				shake_state = 1;
				isRecv = 0;
				isSend = 1;
			}
			char recvCipher[1024] = { '\0' };
			int lenCipher = 1023;
			if (recv(cli, recvCipher, 1024, 0) != SOCKET_ERROR) {
				for (int i = 0; i < 1024; i++) {
					if (!(recvCipher[i] <= '9' && recvCipher[i] >= '0')) {//������ܶ�����Ϣ
						lenCipher = i;
						break;
					}
				}
				memset(recvCipher + lenCipher, 0x0, 1024 - lenCipher - 1);
				bigInt mes_decrypt;
				string strCipher(recvCipher);
				bigInt biCipher(strCipher);
				decrypt_rsa(&biCipher, &mes_decrypt, n_B, d_B);
				if (shake_state == 1 && (isSend || !isRecv)) {//������stage2
					shake_state = 12;
					string temp = bigInt2string(mes_decrypt);
					string N1str = "", N2str = ""; int lenN1;
					for (int i = 0; i < temp.size() - 2; i++) {
						if (!(temp[i] == '|' && temp[i + 1] == '|' && temp[i + 2] == '|')) {
							N1str += temp[i];
						}
						else {
							lenN1 = i;
							break;
						}
					}
					for (int i = lenN1 + 3; i < temp.size(); i++) {
						N2str += temp[i];
					}
					bigInt N1cmp = string2bigInt(N1str);
					N2 = string2bigInt(N2str);
					if (!(N1cmp == N1)) {
						printf("stage 2,N1��ƥ��");
						return 0;
					}
				}
			}

			while (1) {
				if (shake_state == 12) {//�յ��˶Է��������N2��������stage3
					bigInt sN2 = N2;
					bigInt Cipher;
					encrypt_rsa(&sN2, &Cipher, n_A, e_A);

					memcpy_s(sendCipher, 1024, Cipher.getnum().c_str(), Cipher.getnum().size());
					if (send(cli, sendCipher, 1024, 0) >= 0) {
						printf("stage3����Է������У��ѻظ�N2����������stage3\n");
						shake_state = 3;
					}
					bigInt sKey, Key_Cipher,Key_final;
					sKey = random(128, sKey);
					Key = sKey;
					char* temp;
					encrypt_rsa(&sKey, &Key_Cipher, n_B, d_B);
					encrypt_rsa(&Key_Cipher, &Key_final, n_A, e_A);

					memcpy_s(sendCipher, 1024, Key_final.getnum().c_str(), Key_final.getnum().size());
					if (send(cli, sendCipher, 1024, 0) >= 0) {//������stage4
						printf("stage4����Է�������Կ\n");
						shake_state = 5;//��ʼ����AES�Ự����
						break;
					}
				}
			}
			printf("�Ự��Կ�ѷ��ͣ���ʼ����AES�Ự����\n");
		}		
		if (shake_state == 5 && isSend) {//��ʼ����AES�Ự����
			string tmp;
			bigInt IV_big;
			IV_big = random(128, IV_big);
			tmp = bigInt2string(IV_big);
			char mes[1024] = { '\0' }, mes_encrypt[1024]{ '\0' };
			memcpy_s(mes, tmp.size(), tmp.c_str(), tmp.size());
			memcpy_s(IV, 1024, mes, 1024);
			char keytemp[16] = { '\0' };
			memcpy_s(keytemp, 16, bigInt2string(Key).c_str(), 16);
			encrypt_aes(keytemp, mes, mes_encrypt,ECB);
			if (send(cli, (char*)&mes_encrypt, 1024, 0) >= 0);
			shake_state = 6;
			printf("�Ѵ���CBCģʽ��ʼ����IV���Ự�������\n");
		}
		if (shake_state == 6) {//��ʼ����AES�Ự����
			string tmp;
			cin >> tmp;
			char mes[1024] = { '\0' }, mes_encrypt[1024]{ '\0' };
			memcpy_s(mes, tmp.size(), tmp.c_str(), tmp.size());
			char keytemp[16] = { '\0' };
			memcpy_s(keytemp, 16, bigInt2string(Key).c_str(), 16);
			encrypt_aes(keytemp, mes, mes_encrypt,CBC);
			if (send(cli, (char*)&mes_encrypt, 1024, 0) >= 0);
			if (strcmp(tmp.c_str(), "exit") == 0) {
				printf("ֹͣ���У���������Э���˳�\n");
				closesocket(cli);
				return 0;
			}
		}		
	}
	return 0;
}

void decrypt_rsa(bigInt* Cipher, bigInt * mes, bigInt n, bigInt e)
{
	bigInt temp;
	*(mes) = power(*(Cipher), e, n, temp);
}

void encrypt_rsa(bigInt* mes, bigInt* Cipher, bigInt n, bigInt d)
{
	bigInt temp;
	*(Cipher) = power(*(mes), d, n, temp);
}



