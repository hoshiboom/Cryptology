#pragma once
#include <string>
#include <iostream>
using namespace std;
class bigInt
{
public:
	string num;
public:
	string getnum() const;
	bool setnum(string s);
	void print() const;
	bigInt operator * (const bigInt&) const;
	bigInt operator / (const bigInt&) const;
	bigInt operator % (const bigInt&) const;
	bigInt operator + (const bigInt&) const;
	bigInt operator - (const bigInt&) const;
	bool operator == (const bigInt&) const;
	bool operator > (const bigInt&) const;
	bool operator < (const bigInt&) const;
	bool operator >=  (const bigInt&) const;
	bool operator <= (const bigInt&) const;
	bigInt& operator = (const bigInt&);
	friend ostream& operator << (ostream&, const bigInt&);
	friend istream& operator >> (istream&, bigInt&);
	bigInt(string);
	bigInt(const bigInt&);
	bigInt();
};

string toHex(string);
string toDec(string);
bigInt half(bigInt b);
bigInt string2bigInt(string s)
{
	bigInt b("0");
	int l = s.length();
	for (int i = 0; i < l; i++)
	{
		int n = s[i];
		string num(3, '0');
		num[2] += n % 10;
		num[1] += (n / 10) % 10;
		num[0] += (n / 100) % 10;
		b = b * bigInt("128") + bigInt(num);
	}
	return b;
}

string bigInt2string(bigInt b)
{
	bigInt mod("128");
	string res = "";
	while (b > bigInt("0"))
	{

		string s = (b % mod).getnum();
		b = b / mod;
		char c = 0;
		int l = s.length();
		for (int i = 0; i < l; i++)
			c = c * 10 + s[i] - '0';
		//cout << c << endl;
		string tmp(1, c);
		res = c + res;
	}
	return res;
}

