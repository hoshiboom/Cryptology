#pragma once
#include "bigInt.h"
#include "power.h"
#include <ctime>
#include <cstdlib>

void setRandom(unsigned seed) {
    srand(seed);
}

// 返回一个len位的随机数，且为奇数
bigInt random(int len, bigInt& ret) {
    if (len == 0) return bigInt("0");
    if (len == 1) return bigInt("1");
    bigInt x("1");
    for (int i = 1; i < len; i++)
        x = x * bigInt("2");
    string s(len, '0');
    for (int i = 0; i < s.length(); i++)
        s[i] += rand() % 10;
    bigInt res = bigInt(s) % x + x;//结果大于等于2^(len-1)
    //确保是奇数
    if (res % bigInt("2") == bigInt("0"))
        res = res + bigInt("1");
    else
        res = res;
    ret = res;
    return ret;
}
