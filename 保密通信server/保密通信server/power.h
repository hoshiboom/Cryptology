#pragma once
#include "bigInt.h"
#include <string>

using namespace std;
extern bigInt bigInttemp;

bool isodd(bigInt b)
{
	string s = b.getnum();
	return s[s.length() - 1] % 2;
}
//a^b % m
bigInt power(bigInt a, bigInt b, bigInt m, bigInt& temp)
{
	if (b == bigInt("0")) return bigInt("1");
	if (b == bigInt("1")) return a % m;
	bigInt hb = half(b);
	bigInt temp1;
	bigInt phb = power(a, hb, m, temp1);
	temp = (phb * phb) % m;
	if (isodd(b))
		temp = (a * temp) % m;
	return temp;
}
